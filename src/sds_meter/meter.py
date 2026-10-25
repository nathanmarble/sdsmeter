"""Passive real-time damage meter overlay for Seven Deadly Sins: Origin.

Reads game-server traffic with Npcap (npcap.py; Wireshark is not needed) and
decodes P2C_ReportImpact messages. Nothing is injected into, read from, or sent
to the game process; the overlay is an ordinary separate always-on-top window.

Usage (from src/, or run_meter.bat with the same options):
  python -m sds_meter                    live capture (adapter from Cfg > Network, default all)
  python -m sds_meter --iface "Ethernet" live capture on one adapter (name or IPv4, see --list-ifaces)
  python -m sds_meter --port 10005       only this game server port (default: any of 10000-10999)
  python -m sds_meter --pcap file.pcapng replay a capture (testing)
  python -m sds_meter --pcap file.pcapng --nogui   print the meter as text

Overlay: never takes focus from the game; locked it is click-through. One row per
player, stacked; a click on one opens their breakdown (heroes with their portrait,
each hero's skills with the game's skill icon). The only hotkey: Ctrl+Shift+M
lock / unlock. Unlocked: drag the title bar to move, click a player for details
(right-click closes them). The position is saved when you lock it again.

Config tab ("Cfg" in the title bar): separately for your details and for
teammates' details, show each hero separately (tag swaps share one actor id,
so heroes are told apart by their skill names) and/or each skill separately.
Saved in meter_config.json. Icons and skill data come from tools/build_assets.py.
The game must run in windowed/borderless mode for the overlay to be visible.

Key: it is learned from the traffic (~300 messages) and cached in xor_table.bin,
so later sessions decode instantly if it is unchanged. Hits seen while learning
are kept and replayed once the key is known.
"""
import argparse, collections, functools, json, math, os, queue, re, struct, sys, threading, time

from .decode import Reader
from . import netif, npcap, updater

HERE = os.path.dirname(os.path.abspath(__file__))       # this package (src/sds_meter)
# read-only data (icons, json): the project root, two levels up; the packaged exe has it next to the package
ROOT = os.path.dirname(HERE) if "__compiled__" in globals() else os.path.dirname(os.path.dirname(HERE))

APP_VERSION = "1.0.10"       # the exe's product version; the updater compares it to the latest release


def user_dir():
    """Where settings, the key cache and the log are written: the project root, or
    for the packaged exe (its ROOT is a temp folder emptied on exit) %APPDATA%/SDS Meter."""
    if "__compiled__" not in globals():
        return ROOT
    d = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "SDS Meter")
    os.makedirs(d, exist_ok=True)
    return d


USER = user_dir()
TABLE_CACHE = os.path.join(USER, "xor_table.bin")
TABLE_SEED = os.path.join(ROOT, "xor_table.bin")         # optional seed key in the project root, if present
DEBUG_LOG = os.path.join(USER, "meter_debug.log")
DEBUG_LOG_MAX = 20 * 1024 * 1024
MSG_IMPACT, MSG_USE_SKILL, MSG_ABILITY = 10040, 10032, 10100
MSG_SPAWN, MSG_PROPERTY = 10021, 10062        # an actor appears / an actor's value changes
MSG_ROSTER = 10140                            # the dungeon's players: actor id, account, character name
PROP_HP = 4                                  # P2C_ReportProperty type: a monster's HP
# game servers seen on 10001 and 10005 (different server / channel / instance): listen on
# the whole range; the side of the connection using one of these ports is the server
DEFAULT_PORTS = (10000, 10999)
# fallback when nothing arrives on those ports: the game client's own connections
GAME_EXES = ("SevenDeadlySins_Origin-Win64-Shipping.exe",)
WEB_PORTS = {80, 443}                                     # the client's web / API calls, not the game
# damage dealt by skill objects (e.g. Tristan's ultimate bombs) and elemental bursts:
MSG_OBJ_IMPACT, MSG_OBJ_IMPACT_MULTI = 10130, 11054
MSG_BUFFS, MSG_BUFF_END = 10049, 10050                        # buffs put on an actor / one removed
IMPACT_MSGS = (MSG_IMPACT, MSG_OBJ_IMPACT, MSG_OBJ_IMPACT_MULTI)
# the counter resets with the reset button, or after Cfg > "Auto reset" seconds without damage
LEARN_MIN_MSGS = 300


# ---------------------------------------------------------------- capture ---

class LiveCapture:
    """Npcap capture on the chosen adapter ("all" or a friendly name, as in
    netif.adapters()); start() again switches adapters. Remembers which adapter the
    game traffic is on (by the local address the server's packets go to).
    If no server traffic arrives for a while, it asks Windows which ports the game
    client is connected to and follows the server there (see watch())."""

    IDLE = 15           # seconds without server traffic before looking at the client's connections

    def __init__(self, meter, errq, ports):
        self.meter, self.errq, self.ports, self.base = meter, errq, ports, ports
        self.cap, self.sel, self.seen = None, "all", {}           # seen: adapter ip -> time
        self.last_s2c = time.time()
        self.start_lock = threading.Lock()
        threading.Thread(target=self.watch, daemon=True).start()

    def start(self, sel):
        with self.start_lock:
            self._start(sel)

    def _start(self, sel):
        if self.cap:
            self.cap.stop()
        devs = npcap.devices()                       # Npcap names devices by GUID: match by address
        ips = {ip for name, ip in netif.adapters() if sel in (name, ip)}
        chosen = [d for d, _, dips in devs if ips & set(dips)]
        if sel != "all" and not chosen:
            self.errq.put(f"adapter '{sel}' not found, capturing on all adapters")
        chosen = chosen or [d for d, _, dips in devs if dips]
        if not chosen:
            self.errq.put("Npcap lists no connected network adapter")
        self.sel, self.seen = sel, {}
        self.cap = npcap.Capture(chosen, self.ports, self.on_packet, self.errq.put)

    def on_packet(self, t, src, sport, dst, dport, seq, payload):
        if self.ports[0] <= sport <= self.ports[1]:
            self.seen[dst] = self.last_s2c = time.time()  # dst: this PC's address on that adapter
        self.meter.feed(t, src, sport, dst, dport, seq, payload, self.ports)

    def watch(self):
        """Fallback for a server port outside the range: while the game runs but sends
        nothing on self.ports, capture the ports its client is connected to instead,
        and go back to the configured range once the client uses a port in it again."""
        while True:
            time.sleep(5)
            if time.time() - self.last_s2c < self.IDLE:
                continue
            try:
                conns = netif.server_ports(GAME_EXES)
            except OSError:
                continue
            ports = sorted(p for p in conns if p not in WEB_PORTS)
            if not ports or any(self.ports[0] <= p <= self.ports[1] for p in ports):
                continue
            if any(self.base[0] <= p <= self.base[1] for p in ports):
                new = self.base
            else:
                new = (ports[0], ports[-1])
            self.meter.log(time.time(), "no server traffic on ports %d-%d; the game client is connected to %s:"
                           " capturing ports %d-%d" % (*self.ports, ", ".join(f"{conns[p]}:{p}" for p in ports), *new))
            self.ports = self.meter.ports = new
            self.last_s2c = time.time()                      # give the new filter time before checking again
            self.start(self.sel)

    def game_ip(self):
        """Adapter address the game server's packets arrived on in the last 10 s."""
        recent = [(t, ip) for ip, t in self.seen.items() if time.time() - t < 10]
        return max(recent)[1] if recent else None


def port_range(args):
    """(lo, hi) from --port N (one port) or --ports LO-HI (default DEFAULT_PORTS)."""
    if getattr(args, "port", None):
        return args.port, args.port
    spec = getattr(args, "ports", None)
    if spec:
        lo, _, hi = str(spec).partition("-")
        return int(lo), int(hi or lo)
    return DEFAULT_PORTS


class Stream:
    """In-order reassembly of one TCP direction, split into game messages."""

    GAP_WAIT = 1.0      # seconds to wait for a missing segment before skipping it

    def __init__(self):
        self.next_seq, self.pending, self.buf, self.synced = None, {}, bytearray(), False
        self.gap_since = None

    def feed(self, seq, payload, now):
        if self.next_seq is None:
            self.next_seq = seq
        d = (seq - self.next_seq) & 0xFFFFFFFF
        if d >= 0x80000000:                      # retransmit / overlap
            overlap = (self.next_seq - seq) & 0xFFFFFFFF
            if overlap >= len(payload):
                return
            payload, d = payload[overlap:], 0
        if d > 0:                                # out of order, hold it
            self.pending[seq] = payload
            if self.gap_since is None:
                self.gap_since = now
            if now - self.gap_since > self.GAP_WAIT or len(self.pending) > 64:
                # segment lost (capture drop): skip the gap and resync on a header
                self.next_seq = min(self.pending, key=lambda s: (s - self.next_seq) & 0xFFFFFFFF)
                self.buf.clear()
                self.synced = False
            else:
                return
        self.gap_since = None
        if d == 0:
            self.buf += payload
            self.next_seq = (self.next_seq + len(payload)) & 0xFFFFFFFF
        while self.next_seq in self.pending:
            p = self.pending.pop(self.next_seq)
            self.buf += p
            self.next_seq = (self.next_seq + len(p)) & 0xFFFFFFFF

    @staticmethod
    def header_ok(b, i):
        n = int.from_bytes(b[i:i + 2], "big")
        return 13 <= n < 0x8000 and int.from_bytes(b[i + 17:i + 19], "big") == n - 13

    def messages(self):
        b, out = self.buf, []
        i = 0
        while len(b) - i >= 19:
            if not self.synced:                  # started mid-stream: find a header
                if self.header_ok(b, i):
                    self.synced = True
                else:
                    i += 1
                    continue
            n = int.from_bytes(b[i:i + 2], "big") + 6
            if len(b) - i < n:
                break
            if not self.header_ok(b, i):
                self.synced = False
                i += 1
                continue
            out.append(bytes(b[i:i + n]))
            i += n
        del b[:i]
        return out


# ------------------------------------------------------------- decryption ---

class KeyLearner:
    """Keeps the decryption key: cached one first, learned one as fallback."""

    def __init__(self):
        self.cached = None
        for path in (TABLE_CACHE, TABLE_SEED):
            if os.path.exists(path):
                self.cached = open(path, "rb").read()
                break
        if self.cached is not None and len(self.cached) != 256:
            self.cached = None
        self.counts = [collections.Counter() for _ in range(256)]
        self.n_msgs = 0
        self.learned = None
        self.learned_at = 0
        self.confirmed = None                    # table that has decoded hits correctly

    def observe(self, m):
        if len(m) < 22 or self.n_msgs > 20000:
            return
        self.n_msgs += 1
        k = m[16]
        for o in range(19, len(m)):
            self.counts[(k + o) & 0xFF][m[o]] += 1
        if self.n_msgs >= LEARN_MIN_MSGS and self.n_msgs - self.learned_at >= 100:
            self.learned = bytes(c.most_common(1)[0][0] if c else 0 for c in self.counts)
            self.learned_at = self.n_msgs

    def tables(self):
        seen = []
        for t in (self.confirmed, self.learned, self.cached):
            if t is not None and t not in seen:
                seen.append(t)
        return seen

    def confirm(self, table):
        if table != self.confirmed:
            self.confirmed = table
            if table != self.cached:
                try:
                    with open(TABLE_CACHE, "wb") as f:
                        f.write(table)
                except OSError:
                    pass
                self.cached = table

    def status(self):
        if self.confirmed is not None:
            return "key OK"
        if self.cached is not None and self.learned is None:
            return "trying cached key"
        return f"learning key {min(self.n_msgs, LEARN_MIN_MSGS)}/{LEARN_MIN_MSGS}"


def decrypt(m, T):
    k = m[16]
    return bytes(m[o] ^ T[(k + o) & 0xFF] for o in range(19, len(m)))


class BadImpact(ValueError):
    pass


def parse_impact_strict(body, body_len, check_flags=True):
    """decode.parse_impact with sanity checks, so a wrong key is detected.
    Raises BadImpact (or struct.error) with the reason when the message is rejected.
    check_flags is turned off once the key is confirmed, so unusual flag values
    (seen on some skills) do not drop real damage."""
    r = Reader(body)
    caster, _obj, guid = r.u("q"), r.u("q"), r.u("i")
    skill = r.wstr()
    if not skill or len(skill) > 128 or not all(32 < ord(c) < 127 for c in skill):
        raise BadImpact("bad skill name")
    r.u("i"), r.u("i"), r.u("h")
    count = r.u("H")
    if count > 200:
        raise BadImpact(f"{skill}: {count} targets")
    hits = []
    for _ in range(count):
        target, _extra = r.u("q"), r.u("q")
        dtype, damage, hp_after = r.u("H"), r.u("q"), r.u("q")
        r.u("q"), r.u("q"), r.u("i")
        flags = [r.u("B") for _ in range(8)]
        if check_flags and any(f > 1 for f in flags):
            raise BadImpact(f"{skill}: flags {flags}")
        flags = [1 if f else 0 for f in flags]
        no_dmg, no_dmg_local, crit, back, block, _unk, reflect, heal = flags
        r.u("h"), r.u("B"), r.u("h")
        multi = r.u("i")
        r.u("i"), r.u("B")
        if not 0 <= damage < 10 ** 12:
            raise BadImpact(f"{skill}: damage {damage}")
        hits.append(dict(target=target, damage=damage, hp_after=hp_after, crit=crit,
                         back=back, block=block, heal=heal, reflect=reflect,
                         no_damage=no_dmg or no_dmg_local, multi=max(1, multi), dtype=dtype,
                         flags=flags, guid=guid))
    if r.i != body_len:
        raise BadImpact(f"{skill}: parsed {r.i} of {body_len} bytes")
    return caster, skill, hits


def _object_hit(r, target):
    """Layout from the client's packet dump (m_SubAreaIndex ... m_ExtraCasterGUID)."""
    r.u("h")                                    # sub area index
    dtype, damage, hp_after = r.u("h"), r.u("q"), r.u("q")
    r.u("i")                                    # exhaust shield count
    no_dmg, no_dmg_local, crit, heal, block, block_shield = (r.u("B") for _ in range(6))
    skill = r.wstr()                            # attack behavior tid
    r.u("B"), r.u("q")                          # burst active, extra caster
    if not skill or len(skill) > 128 or not all(32 < ord(c) < 127 for c in skill):
        raise BadImpact("bad skill name")
    if not 0 <= damage < 10 ** 12:
        raise BadImpact(f"{skill}: damage {damage}")
    f = [1 if x else 0 for x in (no_dmg, no_dmg_local, crit, heal, block, block_shield)]
    return skill, dict(target=target, damage=damage, hp_after=hp_after, crit=f[2], back=0, block=f[4],
                       heal=f[3], reflect=0, no_damage=f[0] or f[1], multi=1, dtype=dtype, flags=f)


def parse_object_impact(mid, body, body_len):
    """10130 (one hit) / 11054 (several hits): damage dealt by a skill object.
    Every hit has its own skill name, e.g. 'tristan_sworddual_skill_q_dmg' and
    'fire_burstactivation_dmg' in the same message. Returns caster, [(skill, hit)]."""
    r = Reader(body)
    caster = r.u("q")
    if mid == MSG_OBJ_IMPACT:
        target, _obj, _index = r.u("q"), r.u("q"), r.u("i")
        hits = [_object_hit(r, target)]
    else:
        _obj, _index, count = r.u("q"), r.u("i"), r.u("H")
        if count > 200:
            raise BadImpact(f"{count} targets")
        hits = [_object_hit(r, r.u("q")) for _ in range(count)]
    if r.i != body_len:
        raise BadImpact(f"msg {mid}: parsed {r.i} of {body_len} bytes")
    return caster, hits


def parse_buffs(body):
    """P2C_ReportBuffInfoList (10049) -> (caster, target, [(instance, buff id, start, end,
    stacks, source skill)]). Times are the server's clock in ms; end 0 = until removed.
    Layout (reverse engineered): caster, target, u8, u8, u16 count, then per buff:
    instance id, -1, u32 buff id, start, end, u32 stacks, source skill, i64 value."""
    r = Reader(body)
    caster, target = r.u("q"), r.u("q")
    r.u("B"), r.u("B")
    n = r.u("H")
    if n > 256:
        raise BadImpact(f"{n} buffs")
    items = []
    for _ in range(n):
        inst, _x, tid, start, end, stacks = r.u("q"), r.u("q"), r.u("I"), r.u("q"), r.u("q"), r.u("I")
        skill = r.wstr()
        r.u("q")
        items.append((inst, tid, start, end, stacks, skill))
    return caster, target, items


def parse_use_skill(body):
    """C2P_RequestUseSkill -> (hero id, cast id, skill name). The cast id comes
    back as the skill guid of that cast's hits (10040)."""
    r = Reader(body)
    hero, guid = r.u("q"), r.u("i")
    return hero, guid, r.wstr()


# ------------------------------------------------------------------ meter ---

def hero_name(skill):
    """'grade_7_merlin_staff_skill_e' -> 'Merlin'; None for monster skills, items
    and other non-hero skills ('starsbook_skill_rmb_heal', 'epset_ab_attack_lv1')."""
    prefix = split_skill(skill)[0]
    first = prefix.split("_", 1)[0] if prefix else None
    if first is None and (special_key(skill) or "").startswith("charge_"):
        first = special_key(skill)[7:]
    if not first or (HEROES and first not in HEROES):
        return None
    return first.capitalize()


# ------------------------------------------------------------- languages ---

LANGS = ("en", "pt", "fr", "de")
LANG_NAMES = {"en": "English", "pt": "Português", "fr": "Français", "de": "Deutsch"}
_lang = ["en"]
# English text -> (Brazilian Portuguese, French, German); {x} placeholders are kept
TR = {
    # title bar, lists
    "Damage done": ("Dano causado", "Dégâts infligés", "Verursachter Schaden"),
    "Damage taken": ("Dano recebido", "Dégâts subis", "Erhaltener Schaden"),
    "Settings": ("Configurações", "Paramètres", "Einstellungen"),
    "Include monsters": ("Incluir monstros", "Inclure les monstres", "Monster einbeziehen"),
    # Cfg > Network adapter
    "Network adapter": ("Adaptador de rede", "Carte réseau", "Netzwerkadapter"),
    "All adapters (automatic)": ("Todos os adaptadores (automático)", "Toutes les cartes (automatique)",
                                 "Alle Adapter (automatisch)"),
    "Waiting for game traffic": ("Aguardando tráfego do jogo", "En attente du trafic du jeu",
                                 "Warte auf Spieldaten"),
    "Game traffic on: {name}": ("Tráfego do jogo em: {name}", "Trafic du jeu sur : {name}",
                                "Spieldaten über: {name}"),
    "Refresh list": ("Atualizar lista", "Actualiser la liste", "Liste aktualisieren"),
    "not connected": ("não conectado", "non connecté", "nicht verbunden"),
    "Waiting for combat": ("Aguardando combate", "En attente de combat", "Warte auf Kampf"),
    "no damage yet": ("nenhum dano ainda", "aucun dégât pour l'instant", "noch kein Schaden"),
    "no damage taken yet": ("nenhum dano recebido ainda", "aucun dégât subi pour l'instant",
                            "noch kein Schaden erhalten"),
    "defeated": ("derrotado", "vaincu", "besiegt"),
    "HP not reported": ("HP não informado", "PV non transmis", "HP nicht gemeldet"),
    "overkill {n}": ("excesso {n}", "excédent {n}", "Overkill {n}"),
    "Me": ("Eu", "Moi", "Ich"),
    "Player {n}": ("Jogador {n}", "Joueur {n}", "Spieler {n}"),
    "Player names (instead of Player 2, Player 3, ...)": (
        "Nomes dos jogadores (em vez de Jogador 2, Jogador 3, ...)",
        "Noms des joueurs (au lieu de Joueur 2, Joueur 3, ...)",
        "Spielernamen (statt Spieler 2, Spieler 3, ...)"),
    "Enemy {n}": ("Inimigo {n}", "Ennemi {n}", "Gegner {n}"),
    "crit": ("crít", "crit", "Krit"),
    "max": ("máx", "max", "max"),
    # breakdown window
    "#{i} of {n}": ("#{i} de {n}", "#{i} sur {n}", "#{i} von {n}"),
    "not in the list": ("fora da lista", "hors de la liste", "nicht in der Liste"),
    "{p}% of party damage": ("{p}% do dano do grupo", "{p}% des dégâts du groupe", "{p}% des Gruppenschadens"),
    "to {t}": ("em {t}", "sur {t}", "an {t}"),
    "DAMAGE": ("DANO", "DÉGÂTS", "SCHADEN"),
    "DPS": ("DPS", "DPS", "DPS"),
    "CRIT": ("CRÍTICO", "CRITIQUE", "KRIT"),
    "MAX HIT": ("MAIOR GOLPE", "COUP MAX", "MAX. TREFFER"),
    "{n} hits": ("{n} acertos", "{n} coups", "{n} Treffer"),
    "{n} hit": ("{n} acerto", "{n} coup", "{n} Treffer"),
    "avg {v}": ("média {v}", "moy. {v}", "Ø {v}"),
    "No damage yet (or details are off in settings)": (
        "Nenhum dano ainda (ou detalhes desligados nas configurações)",
        "Aucun dégât pour l'instant (ou détails désactivés dans les paramètres)",
        "Noch kein Schaden (oder Details in den Einstellungen aus)"),
    # the unlocked banner
    "Ctrl": ("Ctrl", "Ctrl", "Strg"),
    "lock / unlock": ("travar / destravar", "verrouiller / déverrouiller", "sperren / entsperren"),
    "Breakdown": ("Detalhamento", "Détail", "Aufschlüsselung"),
    "UNLOCKED": ("DESTRAVADO", "DÉVERROUILLÉ", "ENTSPERRT"),
    "Drag a title bar to move · click a player or an enemy": (
        "Arraste a barra de título para mover · clique em um jogador ou inimigo",
        "Glissez une barre de titre pour déplacer · cliquez sur un joueur ou un ennemi",
        "Titelleiste ziehen zum Verschieben · Spieler oder Gegner anklicken"),
    "{k} is used by another program": ("{k} está sendo usado por outro programa",
                                       "{k} est utilisé par un autre programme",
                                       "{k} wird von einem anderen Programm verwendet"),
    # settings
    "Your details": ("Seus detalhes", "Vos détails", "Deine Details"),
    "Teammate details": ("Detalhes dos aliados", "Détails des alliés", "Details der Mitspieler"),
    "Show each hero separately": ("Mostrar cada herói separadamente", "Afficher chaque héros séparément",
                                  "Jeden Helden einzeln zeigen"),
    "Show each skill separately": ("Mostrar cada habilidade separadamente",
                                   "Afficher chaque compétence séparément", "Jede Fähigkeit einzeln zeigen"),
    "Display": ("Exibição", "Affichage", "Anzeige"),
    "Language": ("Idioma", "Langue", "Sprache"),
    "Icons": ("Ícones", "Icônes", "Symbole"),
    "Text": ("Texto", "Texte", "Text"),
    "mini": ("mini", "mini", "mini"),
    "small": ("pequeno", "petit", "klein"),
    "medium": ("médio", "moyen", "mittel"),
    "big": ("grande", "grand", "groß"),
    "giant": ("gigante", "géant", "riesig"),
    "Exact numbers (4,820,000 instead of 4.82M)": ("Números exatos (4,820,000 em vez de 4.82M)",
                                                   "Nombres exacts (4,820,000 au lieu de 4.82M)",
                                                   "Exakte Zahlen (4,820,000 statt 4.82M)"),
    "Opacity": ("Opacidade", "Opacité", "Deckkraft"),
    "Details under the bars (DPS, crit, max hit, enemy HP)": (
        "Detalhes sob as barras (DPS, crítico, maior golpe, HP dos inimigos)",
        "Détails sous les barres (DPS, critique, coup max, PV des ennemis)",
        "Details unter den Balken (DPS, Krit, max. Treffer, Gegner-HP)"),
    "General": ("Geral", "Général", "Allgemein"),
    "Show enemy HP": ("Mostrar HP dos inimigos", "Afficher les PV des ennemis", "Gegner-HP anzeigen"),
    "Max enemy bars": ("Máx. de barras de inimigos", "Barres d'ennemis max.", "Max. Gegnerbalken"),
    "Show monsters in Damage taken": ("Mostrar monstros no Dano recebido",
                                      "Afficher les monstres dans Dégâts subis",
                                      "Monster bei erhaltenem Schaden zeigen"),
    "Start locked (click-through)": ("Iniciar travado (cliques passam direto)",
                                     "Démarrer verrouillé (clics traversants)",
                                     "Gesperrt starten (Klicks gehen durch)"),
    "Max detail rows": ("Máx. de linhas no detalhamento", "Lignes de détail max.", "Max. Detailzeilen"),
    "Auto reset after N s idle (0 = off)": ("Reiniciar após N s sem combate (0 = desligado)",
                                            "Réinitialiser après N s d'inactivité (0 = désactivé)",
                                            "Nach N s Inaktivität zurücksetzen (0 = aus)"),
    # skill names
    "Normal attack": ("Ataque normal", "Attaque normale", "Normaler Angriff"),
    "Jump attack": ("Ataque no ar", "Attaque sautée", "Sprungangriff"),
    "Ultimate": ("Ultimate", "Ultime", "Ultimative"),
    "Tag": ("Troca", "Relais", "Wechsel"),
    "Passive": ("Passiva", "Passif", "Passiv"),
    "Special": ("Especial", "Spécial", "Spezial"),
    "Combo": ("Combo", "Combo", "Kombo"),
    " (enchanted)": (" (encantado)", " (enchanté)", " (verzaubert)"),
    " (evolved)": (" (evoluído)", " (évolué)", " (entwickelt)"),
    "{e} burst": ("Explosão de {e}", "Explosion {e}", "{e}-Ausbruch"),
    "{x} (DoT)": ("{x} (DoT)", "{x} (DoT)", "{x} (DoT)"),
    "{e} DoT": ("DoT de {e}", "DoT {e}", "{e}-DoT"),
    "{e} combo": ("Combo {e}", "Combo {e}", "{e}-Kombo"),
    "Perfect dodge counter": ("Contra-ataque de esquiva perfeita", "Contre d'esquive parfaite",
                              "Konter nach perfektem Ausweichen"),
    "Pet: {x}": ("Mascote: {x}", "Familier : {x}", "Begleiter: {x}"),
    "Transform: {x}": ("Transformação: {x}", "Transformation : {x}", "Verwandlung: {x}"),
    "Food": ("Comida", "Nourriture", "Essen"),
    "Charge attack": ("Ataque carregado", "Attaque chargée", "Aufgeladener Angriff"),
    "{e} crystal": ("Cristal de {e}", "Cristal de {e}", "{e}-Kristall"),
    "Fire": ("Fogo", "Feu", "Feuer"), "Ice": ("Gelo", "Glace", "Eis"), "Wind": ("Vento", "Vent", "Wind"),
    "Thunder": ("Trovão", "Foudre", "Donner"), "Earth": ("Terra", "Terre", "Erde"),
    "Holy": ("Sagrado", "Sacré", "Heilig"), "Dark": ("Trevas", "Ténèbres", "Dunkel"),
    "Burn": ("Queimadura", "Brûlure", "Verbrennung"), "Bleed": ("Sangramento", "Saignement", "Blutung"),
    "Poison": ("Veneno", "Poison", "Gift"), "Shock": ("Choque", "Choc", "Schock"),
    "Curse": ("Maldição", "Malédiction", "Fluch"), "Corrosion": ("Corrosão", "Corrosion", "Korrosion"),
    "Freeze": ("Congelamento", "Gel", "Einfrieren"), "Frostbite": ("Ulceração", "Engelure", "Erfrierung"),
    "Weapon": ("Arma", "Arme", "Waffe"), "Gear": ("Equipamento", "Équipement", "Ausrüstung"),
    "Limit break": ("Superação", "Transcendance", "Limitbruch"), "Armor": ("Armadura", "Armure", "Rüstung"),
    "Accessory": ("Acessório", "Accessoire", "Zubehör"), "Set": ("Conjunto", "Ensemble", "Set"),
}


# tutorial: (title, text) per step, English; translations in TR below
TUTORIAL = (
    ("Welcome to SDS Meter",
     "SDS Meter shows the damage of everyone in your party while you play. It only reads the game's "
     "network traffic: nothing is sent to the game and nothing in it is changed. This tour shows every "
     "feature in about two minutes."),
    ("The damage list",
     "Each row is a player, ranked by damage. The bar compares them with the top player, the % is their "
     "share of the party's damage, and the small line shows damage per second, crit rate and biggest hit (turn that line off in the settings for thinner bars). "
     "Your own row is amber, and the top 3 get gold, silver and bronze badges."),
    ("Done and Taken",
     "The D / T button in the title bar changes the list between D, damage done (dealt), and T, damage "
     "taken (received): click it and pick one. In damage taken, the 'Include monsters' switch at the top "
     "also lists the damage monsters took."),
    ("Enemy HP",
     "Enemies you hit appear as red bars at the top, shrinking as their HP drops. Click one and the "
     "list shows only the damage dealt to that enemy. The chosen "
     "enemy is outlined in yellow; click it again to go back to all damage."),
    ("Damage breakdown",
     "Click a player to open their breakdown in a separate window (yours opens by "
     "itself when a fight starts): damage, DPS, crit and max hit at the top, then each hero's damage. The "
     "size button in its title also shows each of their skills, with hits, average hit and overkill. Use "
     "the < > buttons to switch players."),
    ("Damage over time",
     "The Graph tab of the breakdown (click it) draws each player's damage per second "
     "across the fight, the selected player thicker, with the boss's or chosen enemy's HP as a dashed "
     "line."),
    ("Boss fights",
     "In boss mode the fight ends when the boss dies, and is saved. Bosses that level up when killed, like"
     " the guild boss, show their level and kills on their HP bar, and when one starts charging its "
     "ultimate the watch bar counts down to the hit. The guild boss score has a small window of its own, "
     "turned on with the windows button: your points live (rounded up, like the server's), the server's "
     "score at each level-up and the final one. During its ultimate, the guild boss's five crystals show "
     "in the enemy bars by element (Fire crystal, Earth crystal, ...)."),
    ("Skill rotation",
     "The rotation button on your breakdown or the windows button opens your skill rotation: "
     "every skill you cast, in order, with the key you pressed, the time and the damage it dealt. The size "
     "button in its title (or its wrench) switches to a compact view with only the icons."),
    ("Buffs and debuffs",
     "The windows button opens the Effects window: Live shows what is on you, your teammates and the "
     "enemies right now, Log lists every effect applied, by whom and on whom, and Uptime shows how much of"
     " the fight each one was up. Its wrench shows the game's hidden effects and turns the watch bar on or"
     " off."),
    ("Watch bar",
     "Click any effect, or pick one by its icon under 'Choose effects', to watch it. Watched effects stay "
     "on a small bar you can place anywhere: lit with their time left while they are on, dimmed while off,"
     " also effects the game itself doesn't show."),
    ("Fight history",
     "Every fight is saved when it ends: a boss kill, a reset, or 60 seconds without combat. The Fight "
     "history window (windows button) lists them, the fight going on at the top; click one to see it "
     "here again, and use Export / Import to share fights."),
    ("Lock and unlock",
     "Unlocked, you can drag the windows by their title bars and click players, enemies and buttons. "
     "Locked, clicks pass through the windows to the game. Switch with the lock button or Ctrl+Shift+M, "
     "the only key (the UNLOCKED banner under the meter shows it). Drag a window's bottom-right corner "
     "(◢) to resize it: bars stretch, rows that don't fit scroll, and text and icons get smaller when "
     "it gets narrow; double-click the corner for its own size. The windows remember where you put them "
     "and their size."),
    ("The title bar",
     "The dot shows the connection: green when live, amber while waiting for the game, red on an error. "
     "Next to it is the fight timer. The buttons are: D / T (damage done or taken), windows, settings, this "
     "tutorial, reset the fight, lock, and close."),
    ("Settings and windows",
     "The windows button opens or closes each window, also before a fight, so you can put them in "
     "place: the breakdown, skill rotation, effects, watch bar, fight history and guild boss score. The "
     "gear button opens the settings: language, icon and text size, exact numbers, "
     "the details under the bars, opacity, enemy bars, boss mode, clearing the meter after N seconds without combat (60 by default), "
     "start locked and reset window positions. A window with options of its own has "
     "a wrench in its title: what the breakdown shows, the rotation's compact view, hidden effects."),
    ("You're all set",
     "Start a fight and the meter fills in by itself; after 60 seconds without combat it clears and the "
     "fight goes to the history. The reset button clears it by hand. You can open this tutorial again any"
     " time with the ? button."),
)
TUTORIAL_TR = {
    "pt": (
        ("Bem-vindo ao SDS Meter",
         "O SDS Meter mostra o dano de todos do seu grupo enquanto você joga. Ele só lê o tráfego de rede "
         "do jogo: nada é enviado ao jogo e nada nele é alterado. Este tour mostra todos os recursos em "
         "cerca de dois minutos."),
        ("A lista de dano",
         "Cada linha é um jogador, ordenado por dano. A barra compara com o primeiro colocado, a % é a "
         "parte dele no dano do grupo, e a linha menor mostra dano por segundo, taxa de crítico e maior "
         "golpe (desligue essa linha nas configurações para barras mais finas). Sua linha fica em âmbar, e os 3 primeiros ganham medalhas de ouro, prata e bronze."),
        ("Causado e Recebido",
         "O botão D / T na barra de título alterna a lista entre D, dano causado, e T, dano recebido: "
         "clique nele e escolha. Em dano recebido, a opção 'Incluir monstros' no topo também lista o dano "
         "recebido pelos monstros."),
        ("HP dos inimigos",
         "Os inimigos que você acerta aparecem como barras vermelhas no topo, diminuindo conforme o HP "
         "cai. Clique em um e a lista mostra só o dano "
         "causado a esse inimigo. O inimigo escolhido fica com contorno amarelo; clique de novo para "
         "voltar a todo o dano."),
        ("Detalhamento de dano",
         "Clique em um jogador para abrir os detalhes dele em uma janela separada"
         " (os seus abrem sozinhos quando uma luta começa): dano, DPS, crítico e maior golpe no topo, "
         "depois o dano de cada herói. O botão de tamanho no título mostra também cada habilidade, com "
         "acertos, média por acerto e dano excedente. Use os botões < > para "
         "trocar de jogador."),
        ("Dano ao longo do tempo",
         "A aba Gráfico dos detalhes (clique nela) mostra o dano por segundo de cada "
         "jogador durante a luta, o jogador escolhido mais grosso, com o HP do chefe ou do inimigo "
         "escolhido em linha tracejada."),
        ("Lutas contra chefes",
         "No modo chefe a luta termina quando o chefe morre, e é salva. Chefes que sobem de nível ao serem"
         " derrotados, como o chefe da guilda, mostram o nível e os abates na barra de HP, e quando um "
         "começa a carregar o ultimate, a barra de acompanhamento conta o tempo até o golpe. Os pontos do "
         "chefe da guilda têm uma janelinha própria, ligada pelo botão de janelas: seus pontos ao vivo (arredondados para cima, como os do "
         "servidor), os pontos do servidor a cada nível e os finais. Durante o ultimate, os cinco cristais "
         "do chefe da guilda aparecem nas barras de inimigos pelo elemento (Cristal de Fogo, Cristal de "
         "Terra, ...)."),
        ("Rotação de skills",
         "O botão de rotação nos seus detalhes ou o botão de janelas abre a sua rotação "
         "de skills: cada skill que você usou, em ordem, com a tecla apertada, o tempo e o dano que causou. "
         "O botão de tamanho no título dela (ou a chave inglesa) troca para uma vista compacta só com os "
         "ícones."),
        ("Buffs e debuffs",
         "O botão de janelas abre a janela de Efeitos: Agora mostra o que está em você, nos seus "
         "aliados e nos inimigos neste momento, Registro lista cada efeito aplicado, por quem e em quem, e "
         "Tempo ativo mostra quanto da luta cada um ficou ativo. A chave inglesa dela mostra os efeitos "
         "ocultos do jogo e liga ou desliga a barra de acompanhamento."),
        ("Barra de acompanhamento",
         "Clique em qualquer efeito, ou escolha um pelo ícone em 'Escolher efeitos', para acompanhá-lo. Os"
         " efeitos acompanhados ficam numa barra pequena que você pode pôr em qualquer lugar: acesos com o"
         " tempo restante quando ativos, apagados quando não, inclusive efeitos que o próprio jogo não "
         "mostra."),
        ("Histórico de lutas",
         "Cada luta é salva quando termina: chefe derrotado, reset ou 60 segundos sem combate. A janela "
         "Histórico de lutas (botão de janelas) lista todas, com a luta atual no topo; clique em "
         "uma para vê-la aqui de novo, e use Exportar / Importar para compartilhar lutas."),
        ("Travar e destravar",
         "Destravado, você pode arrastar as janelas pela barra de título e clicar em jogadores, "
         "inimigos e botões. Travado, os cliques passam direto para o jogo. Alterne com o botão de cadeado"
         " ou Ctrl+Shift+M, a única tecla (a faixa DESTRAVADO embaixo do medidor mostra). Arraste o canto "
         "inferior direito de uma janela (◢) para redimensioná-la: as barras se esticam, as linhas que não "
         "cabem rolam, e texto e ícones diminuem quando ela fica estreita; clique duas vezes no canto para "
         "o tamanho dela. As janelas lembram onde você as deixou e o tamanho."),
        ("A barra de título",
         "O ponto mostra a conexão: verde quando ao vivo, âmbar esperando o jogo, vermelho em caso de "
         "erro. Ao lado fica o tempo da luta. Os botões são: D / T (dano causado ou recebido), "
         "janelas, configurações, este tutorial, resetar a luta, travar e fechar."),
        ("Configurações e janelas",
         "O botão de janelas abre ou fecha cada janela, também antes de uma luta, para você "
         "posicioná-las: detalhes, rotação de skills, efeitos, barra de acompanhamento, histórico de lutas "
         "e pontos do chefe da guilda. A engrenagem abre as configurações: idioma, tamanho de "
         "ícones e texto, números exatos, os detalhes sob as barras, opacidade, barras de inimigos, modo chefe, limpar o medidor após "
         "N segundos sem combate (60 por padrão), iniciar travado e redefinir a posição "
         "das janelas. Uma janela com opções próprias tem uma chave inglesa no título: o que os detalhes "
         "mostram, a vista compacta da rotação, os efeitos ocultos."),
        ("Tudo pronto",
         "Comece uma luta e o medidor se preenche sozinho; após 60 segundos sem combate ele limpa e a luta"
         " vai para o histórico. O botão de reset limpa manualmente. Você pode abrir este "
         "tutorial de novo a qualquer momento com o botão ?."),
    ),
    "fr": (
        ("Bienvenue dans SDS Meter",
         "SDS Meter affiche les dégâts de tout votre groupe pendant que vous jouez. Il lit seulement le "
         "trafic réseau du jeu : rien n'est envoyé au jeu et rien n'y est modifié. Cette visite présente "
         "toutes les fonctions en deux minutes environ."),
        ("La liste des dégâts",
         "Chaque ligne est un joueur, classé par dégâts. La barre le compare au premier, le % est sa part "
         "des dégâts du groupe, et la petite ligne indique les dégâts par seconde, le taux de critique et "
         "le plus gros coup (désactivez cette ligne dans les paramètres pour des barres plus fines). Votre ligne est ambrée, et les 3 premiers ont un badge or, argent et bronze."),
        ("Infligés et Subis",
         "Le bouton D / T de la barre de titre fait passer la liste de D, dégâts infligés, à T, dégâts "
         "subis : cliquez dessus et choisissez. Dans les dégâts subis, l'option « Inclure les monstres » en "
         "haut ajoute aussi les dégâts subis par les monstres."),
        ("PV des ennemis",
         "Les ennemis que vous touchez apparaissent en barres rouges en haut, qui raccourcissent quand "
         "leurs PV baissent. Cliquez sur l'un d'eux et la"
         " liste n'affiche que les dégâts infligés à cet ennemi. L'ennemi choisi est entouré en jaune ; "
         "cliquez à nouveau pour revenir à tous les dégâts."),
        ("Détail des dégâts",
         "Cliquez sur un joueur pour ouvrir son détail dans une fenêtre "
         "séparée (le vôtre s'ouvre tout seul au début d'un combat) : dégâts, DPS, critique et plus gros "
         "coup en haut, puis les dégâts de chaque héros. Le bouton de taille de son titre affiche aussi "
         "chacune de ses compétences, avec coups, moyenne et excédent. Utilisez les boutons < > "
         "pour changer de joueur."),
        ("Dégâts dans le temps",
         "L'onglet Graphique du détail (cliquez dessus) trace les dégâts par seconde de"
         " chaque joueur pendant le combat, le joueur choisi plus épais, avec les PV du boss ou de "
         "l'ennemi choisi en pointillés."),
        ("Combats de boss",
         "En mode boss, le combat se termine à la mort du boss, et il est enregistré. Les boss qui montent"
         " de niveau quand on les bat, comme le boss de guilde, affichent leur niveau et leurs "
         "éliminations sur leur barre de PV, et quand l'un d'eux charge son ultime, la barre de suivi "
         "compte à rebours jusqu'au coup. Le score du boss de guilde a sa propre petite fenêtre, activée "
         "avec le bouton fenêtres : vos points en direct (arrondis au supérieur, comme ceux du serveur), "
         "le score du serveur à chaque niveau et le score final. Pendant son ultime, les cinq cristaux du "
         "boss de guilde apparaissent dans les barres d'ennemis par élément (Cristal de Feu, Cristal de "
         "Terre, ...)."),
        ("Rotation de compétences",
         "Le bouton rotation de votre détail ou le bouton fenêtres ouvre votre rotation : "
         "chaque compétence lancée, dans l'ordre, avec la touche utilisée, le moment et les dégâts infligés."
         " Le bouton de taille de son titre (ou sa clé) passe à une vue compacte avec seulement les icônes."),
        ("Buffs et debuffs",
         "Le bouton fenêtres ouvre la fenêtre Effets : En direct montre ce qui est actif sur vous, vos "
         "alliés et les ennemis en ce moment, Journal liste chaque effet appliqué, par qui et sur qui, et "
         "Temps actif indique quelle part du combat chacun est resté actif. Sa clé affiche les effets "
         "cachés du jeu et active ou désactive la barre de suivi."),
        ("Barre de suivi",
         "Cliquez sur un effet, ou choisissez-le par son icône dans « Choisir des effets », pour le "
         "suivre. Les effets suivis restent sur une petite barre que vous placez où vous voulez : allumés "
         "avec leur temps restant quand ils sont actifs, grisés sinon, même les effets que le jeu "
         "n'affiche pas."),
        ("Historique des combats",
         "Chaque combat est enregistré à sa fin : boss vaincu, réinitialisation ou 60 secondes sans "
         "combat. La fenêtre Historique des combats (bouton fenêtres) les liste, le combat en cours "
         "en haut ; cliquez sur l'un pour le revoir ici, et utilisez Exporter / Importer pour partager des "
         "combats."),
        ("Verrouiller et déverrouiller",
         "Déverrouillées, les fenêtres se déplacent par leur barre de titre et vous pouvez cliquer "
         "sur les joueurs, ennemis et boutons. Verrouillées, elles laissent passer les clics vers le jeu. "
         "Basculez avec le bouton cadenas ou Ctrl+Shift+M, la seule touche (le bandeau DÉVERROUILLÉ sous "
         "le compteur l'affiche). Faites glisser le coin inférieur droit d'une fenêtre (◢) pour la "
         "redimensionner : les barres s'étirent, les lignes en trop défilent, et texte et icônes "
         "rapetissent quand elle devient étroite ; double-cliquez sur le coin pour sa taille d'origine. "
         "Les fenêtres retiennent leur position et leur taille."),
        ("La barre de titre",
         "Le point indique la connexion : vert en direct, ambre en attente du jeu, rouge en cas d'erreur. "
         "À côté se trouve la durée du combat. Les boutons sont : D / T (dégâts infligés ou subis), "
         "fenêtres, paramètres, ce tutoriel, réinitialiser, verrouiller et fermer."),
        ("Paramètres et fenêtres",
         "Le bouton fenêtres ouvre ou ferme chaque fenêtre, aussi avant un combat, pour les mettre en "
         "place : détail, rotation de compétences, effets, barre de suivi, historique des combats et score "
         "du boss de guilde. La roue dentée ouvre les paramètres : langue, taille des "
         "icônes et du texte, nombres exacts, les détails sous les barres, opacité, barres d'ennemis, mode boss, vider le compteur après "
         "N secondes sans combat (60 par défaut), démarrer verrouillé et "
         "réinitialiser la position des fenêtres. Une fenêtre qui a ses propres options a une clé dans son "
         "titre : ce que montre le détail, la vue compacte de la rotation, les effets cachés."),
        ("Tout est prêt",
         "Lancez un combat et le compteur se remplit tout seul ; après 60 secondes sans combat il se vide "
         "et le combat va dans l'historique. Le bouton de réinitialisation le vide à la main. Vous "
         "pouvez rouvrir ce tutoriel à tout moment avec le bouton ?."),
    ),
    "de": (
        ("Willkommen bei SDS Meter",
         "SDS Meter zeigt beim Spielen den Schaden deiner ganzen Gruppe. Es liest nur den Netzwerkverkehr "
         "des Spiels: Nichts wird an das Spiel gesendet und nichts darin verändert. Diese Tour zeigt alle "
         "Funktionen in etwa zwei Minuten."),
        ("Die Schadensliste",
         "Jede Zeile ist ein Spieler, nach Schaden sortiert. Der Balken vergleicht ihn mit dem Ersten, die"
         " % sind sein Anteil am Gruppenschaden, und die kleine Zeile zeigt Schaden pro Sekunde, Kritrate "
         "und höchsten Treffer (in den Einstellungen abschaltbar, für schmalere Balken). Deine Zeile ist bernsteinfarben, die ersten 3 bekommen Gold-, Silber- und "
         "Bronzeabzeichen."),
        ("Verursacht und Erhalten",
         "Der Knopf D / T in der Titelleiste wechselt die Liste zwischen D, verursachter Schaden, und T, "
         "erhaltener Schaden: anklicken und wählen. Bei erhaltenem Schaden listet der Schalter „Monster "
         "einbeziehen“ oben auch den Schaden, den Monster erhalten."),
        ("Gegner-HP",
         "Getroffene Gegner erscheinen oben als rote Balken, die mit ihren HP schrumpfen. Klicke einen an "
         "und die Liste zeigt nur den Schaden an diesem "
         "Gegner. Der gewählte Gegner ist gelb umrandet; klicke erneut, um wieder allen Schaden zu sehen."),
        ("Schadensaufschlüsselung",
         "Klicke auf einen Spieler, um seine Aufschlüsselung in einem eigenen "
         "Fenster zu öffnen (deine öffnet sich bei Kampfbeginn von selbst): Schaden, DPS, Krit und "
         "höchster Treffer oben, darunter der Schaden jedes Helden. Der Größen-Knopf im Titel zeigt auch "
         "jede seiner Fähigkeiten mit Treffern, Durchschnitt und Überschaden. Mit den Knöpfen < > "
         "wechselst du den Spieler."),
        ("Schaden über die Zeit",
         "Der Reiter Grafik der Aufschlüsselung (anklicken) zeigt den Schaden pro "
         "Sekunde jedes Spielers über den Kampf, den gewählten Spieler dicker, mit den HP des Bosses oder "
         "des gewählten Gegners gestrichelt."),
        ("Bosskämpfe",
         "Im Boss-Modus endet der Kampf mit dem Tod des Bosses und wird gespeichert. Bosse, die beim "
         "Besiegen aufsteigen, wie der Gildenboss, zeigen Stufe und Kills auf ihrem HP-Balken, und wenn "
         "einer sein Ultimate auflädt, zählt die Beobachtungsleiste bis zum Treffer herunter. Die Punkte "
         "des Gildenbosses haben ein eigenes kleines Fenster, einzuschalten über den Fenster-Knopf: deine Punkte live (aufgerundet "
         "wie die des Servers), die Serverpunkte bei jedem Stufenaufstieg und die Endpunktzahl. Während "
         "seines Ultimates erscheinen die fünf Kristalle des Gildenbosses in den Gegnerbalken nach Element "
         "(Feuer-Kristall, Erde-Kristall, ...)."),
        ("Skill-Rotation",
         "Der Rotations-Knopf deiner Aufschlüsselung oder der Fenster-Knopf öffnet "
         "deine Skill-Rotation: jeder eingesetzte Skill der Reihe nach, mit der gedrückten Taste, dem "
         "Zeitpunkt und dem Schaden. Der Größen-Knopf in ihrem Titel (oder ihr Schraubenschlüssel) wechselt"
         " zu einer kompakten Ansicht nur mit Symbolen."),
        ("Buffs und Debuffs",
         "Der Fenster-Knopf öffnet das Effekte-Fenster: Live zeigt, was gerade auf dir, deinen "
         "Mitspielern und den Gegnern liegt, Protokoll listet jeden angewendeten Effekt, von wem auf wen, "
         "und Aktivzeit zeigt, wie lange jeder im Kampf aktiv war. Sein Schraubenschlüssel zeigt die "
         "versteckten Effekte des Spiels und schaltet die Beobachtungsleiste ein oder aus."),
        ("Beobachtungsleiste",
         "Klicke auf einen Effekt oder wähle ihn unter „Effekte wählen“ an seinem Symbol, um ihn zu "
         "beobachten. Beobachtete Effekte bleiben auf einer kleinen Leiste, die du überall hinlegen "
         "kannst: hell mit Restzeit, solange sie aktiv sind, sonst abgedunkelt, auch Effekte, die das "
         "Spiel selbst nicht anzeigt."),
        ("Kampfverlauf",
         "Jeder Kampf wird an seinem Ende gespeichert: Boss besiegt, Zurücksetzen oder 60 Sekunden ohne "
         "Kampf. Das Fenster Kampfverlauf (Fenster-Knopf) listet sie, den laufenden Kampf oben; "
         "klicke einen an, um ihn hier wieder anzusehen, und nutze Exportieren / Importieren zum Teilen."),
        ("Sperren und entsperren",
         "Entsperrt kannst du die Fenster an der Titelleiste ziehen und Spieler, Gegner und Knöpfe "
         "anklicken. Gesperrt gehen Klicks durch die Fenster zum Spiel. Wechsle mit dem Schloss-Knopf oder"
         " Strg+Shift+M, die einzige Taste (das ENTSPERRT-Banner unter dem Meter zeigt sie). Ziehe die "
         "untere rechte Ecke eines Fensters (◢), um seine Größe zu ändern: Balken strecken sich, Zeilen, "
         "die nicht passen, scrollen, und Text und Symbole werden kleiner, wenn es schmal wird; ein "
         "Doppelklick auf die Ecke gibt ihm seine eigene Größe zurück. Die Fenster merken sich Position "
         "und Größe."),
        ("Die Titelleiste",
         "Der Punkt zeigt die Verbindung: grün bei live, bernsteinfarben beim Warten auf das Spiel, rot "
         "bei einem Fehler. Daneben steht die Kampfzeit. Die Knöpfe sind: D / T (verursachter oder "
         "erhaltener Schaden), Fenster, Einstellungen, dieses Tutorial, Kampf zurücksetzen, sperren und schließen."),
        ("Einstellungen und Fenster",
         "Der Fenster-Knopf öffnet oder schließt jedes Fenster, auch vor einem Kampf, damit du sie "
         "platzieren kannst: Aufschlüsselung, Skill-Rotation, Effekte, Beobachtungsleiste, Kampfverlauf und "
         "Gildenboss-Punkte. Das Zahnrad öffnet die Einstellungen: Sprache, Symbol- und "
         "Textgröße, exakte Zahlen, Details unter den Balken, Deckkraft, Gegnerbalken, Boss-Modus, Meter nach N Sekunden ohne Kampf "
         "leeren (standardmäßig 60), gesperrt starten und Fensterpositionen zurücksetzen."
         " Ein Fenster mit eigenen Optionen hat einen Schraubenschlüssel im Titel: was die Aufschlüsselung "
         "zeigt, die kompakte Ansicht der Rotation, versteckte Effekte."),
        ("Alles bereit",
         "Starte einen Kampf und der Meter füllt sich von selbst; nach 60 Sekunden ohne Kampf leert er "
         "sich und der Kampf landet im Verlauf. Der Zurücksetzen-Knopf leert ihn von Hand. Dieses "
         "Tutorial kannst du jederzeit über den ?-Knopf wieder öffnen."),
    ),
}
TR.update({
    "Step {i} of {n}": ("Passo {i} de {n}", "Étape {i} sur {n}", "Schritt {i} von {n}"),
    "Back": ("Voltar", "Retour", "Zurück"),
    "Next": ("Próximo", "Suivant", "Weiter"),
    "Finish": ("Concluir", "Terminer", "Fertig"),
    "Skip tutorial": ("Pular tutorial", "Passer le tutoriel", "Tutorial überspringen"),
    "Show tutorial": ("Ver tutorial", "Voir le tutoriel", "Tutorial ansehen"),
    "Hi! Welcome to SDS Meter": ("Olá! Bem-vindo ao SDS Meter", "Bonjour ! Bienvenue dans SDS Meter",
                                 "Hallo! Willkommen bei SDS Meter"),
    "It shows your party's damage live while you play. Want a quick tour of everything it can do?": (
        "Ele mostra o dano do seu grupo ao vivo enquanto você joga. Quer um tour rápido por tudo o que ele faz?",
        "Il affiche les dégâts de votre groupe en direct pendant que vous jouez. Voulez-vous une visite "
        "rapide de tout ce qu'il sait faire ?",
        "Es zeigt beim Spielen live den Schaden deiner Gruppe. Möchtest du eine kurze Tour durch alle "
        "Funktionen?"),
    "Reset window positions": ("Redefinir posição das janelas", "Réinitialiser la position des fenêtres",
                               "Fensterpositionen zurücksetzen"),
    "Positions reset": ("Posições redefinidas", "Positions réinitialisées", "Positionen zurückgesetzt"),
    "Preview": ("Prévia", "Aperçu", "Vorschau"),
    "Fight history": ("Histórico de lutas", "Historique des combats", "Kampfverlauf"),
    "Import…": ("Importar…", "Importer…", "Importieren…"),
    "Export…": ("Exportar…", "Exporter…", "Exportieren…"),
    "Back to live": ("Voltar ao vivo", "Retour au direct", "Zurück zu live"),
    "HISTORY": ("HISTÓRICO", "HISTORIQUE", "VERLAUF"),
    "BOSS": ("CHEFE", "BOSS", "BOSS"),
    "click here: back to live": ("clique aqui: voltar ao vivo", "cliquez ici : retour au direct",
                                 "hier klicken: zurück zu live"),
    "defeated in {t}": ("derrotado em {t}", "vaincu en {t}", "besiegt in {t}"),
    "party {d}  ·  {p}/s": ("grupo {d}  ·  {p}/s", "groupe {d}  ·  {p}/s", "Gruppe {d}  ·  {p}/s"),
    "party": ("grupo", "groupe", "Gruppe"),
    "you": ("você", "vous", "du"),
    "Damage": ("Dano", "Dégâts", "Schaden"),
    "Buffs": ("Buffs", "Buffs", "Buffs"),
    "Graph": ("Gráfico", "Graphique", "Grafik"),
    "Buffs on {p}": ("Buffs em {p}", "Buffs sur {p}", "Buffs auf {p}"),
    "Debuffs {p} applied": ("Debuffs aplicados por {p}", "Debuffs appliqués par {p}", "Debuffs von {p}"),
    "Debuffs from enemies": ("Debuffs dos inimigos", "Debuffs des ennemis", "Debuffs von Gegnern"),
    "applied {n}×": ("aplicado {n}×", "appliqué {n}×", "{n}× angewendet"),
    "avg {s}s": ("média {s}s", "moy. {s}s", "Ø {s}s"),
    "{s}s in total": ("{s}s no total", "{s}s au total", "{s}s insgesamt"),
    "No buffs or debuffs recorded yet": ("Nenhum buff ou debuff registrado ainda", "Aucun buff ni debuff enregistré",
                                         "Noch keine Buffs oder Debuffs erfasst"),
    "No damage over time yet": ("Ainda sem dano ao longo do tempo", "Pas encore de dégâts dans le temps",
                                "Noch kein Schaden über die Zeit"),
    "No fights yet": ("Nenhuma luta ainda", "Aucun combat pour l'instant", "Noch keine Kämpfe"),
    "LIVE": ("AO VIVO", "EN DIRECT", "LIVE"),
    "Boss mode: a boss kill ends the fight (saved to the history)": (
        "Modo chefe: derrotar um chefe encerra a luta (salva no histórico)",
        "Mode boss : vaincre un boss termine le combat (enregistré dans l'historique)",
        "Boss-Modus: ein besiegter Boss beendet den Kampf (im Verlauf gespeichert)"),
    "Could not open {f}: {e}": ("Não foi possível abrir {f}: {e}", "Impossible d'ouvrir {f} : {e}",
                                "{f} konnte nicht geöffnet werden: {e}"),
    "Could not save {f}: {e}": ("Não foi possível salvar {f}: {e}", "Impossible d'enregistrer {f} : {e}",
                                "{f} konnte nicht gespeichert werden: {e}"),
    "No fight to export yet": ("Nenhuma luta para exportar ainda", "Aucun combat à exporter",
                               "Noch kein Kampf zum Exportieren"),
    "Import a fight": ("Importar uma luta", "Importer un combat", "Einen Kampf importieren"),
    "Export the fight": ("Exportar a luta", "Exporter le combat", "Den Kampf exportieren"),
    "SDS Meter fight": ("Luta do SDS Meter", "Combat SDS Meter", "SDS-Meter-Kampf"),
    "Enemy": ("Inimigo", "Ennemi", "Gegner"),
    "Fight": ("Luta", "Combat", "Kampf"),
    "HP": ("HP", "PV", "HP"),
    "Buff #{n}": ("Buff nº {n}", "Buff n° {n}", "Buff Nr. {n}"),
    "ULTIMATE": ("ULTIMATE", "ULTIME", "ULTIMATE"),
    "SCORE": ("PONTOS", "SCORE", "PUNKTE"),
    "Guild ranking": ("Ranking da guilda", "Classement de guilde", "Gildenrangliste"),
    "final score of the run": ("pontuação final da partida", "score final de la partie", "Endpunktzahl des Laufs"),
    "server: {s} at Lv {n}": ("servidor: {s} no Nv {n}", "serveur : {s} au niv {n}", "Server: {s} bei Lv {n}"),
    "Ultimate": ("Ultimate", "Ultime", "Ultimate"),
    "Boss": ("Chefe", "Boss", "Boss"),
    "charging: lands in {s}s": ("carregando: atinge em {s}s", "en charge : frappe dans {s}s", "lädt: trifft in {s}s"),
    "not charging": ("sem carregar", "pas en charge", "lädt nicht"),
    "{n}× this fight": ("{n}× nesta luta", "{n}× dans ce combat", "{n}× in diesem Kampf"),
    "last: {d} at {t}": ("último: {d} em {t}", "dernière : {d} à {t}", "zuletzt: {d} bei {t}"),
    "hardest on {p}: {d}": ("mais forte em {p}: {d}", "plus fort sur {p} : {d}", "am stärksten auf {p}: {d}"),
    "Lv {n}/{m}": ("Nv {n}/{m}", "Niv {n}/{m}", "Lv {n}/{m}"),
    "{n} kills": ("{n} abates", "{n} éliminations", "{n} Kills"),
    "Effects": ("Efeitos", "Effets", "Effekte"),
    "Live": ("Agora", "En direct", "Live"),
    "Log": ("Registro", "Journal", "Protokoll"),
    "Uptime": ("Tempo ativo", "Temps actif", "Aktivzeit"),
    "Show hidden effects": ("Mostrar efeitos ocultos", "Afficher les effets cachés", "Versteckte Effekte zeigen"),
    "hidden": ("oculto", "caché", "versteckt"),
    "Click an effect to watch it (★): while it is on, it shows on the watch bar with its time left.": (
        "Clique em um efeito para acompanhá-lo (★): enquanto estiver ativo, ele aparece na barra com o tempo restante.",
        "Cliquez sur un effet pour le suivre (★) : tant qu'il est actif, il s'affiche dans la barre avec son temps restant.",
        "Klicke auf einen Effekt, um ihn zu beobachten (★): solange er aktiv ist, steht er mit Restzeit in der Leiste."),
    "On {t}": ("Em {t}", "Sur {t}", "Auf {t}"),
    "by {p}": ("por {p}", "par {p}", "von {p}"),
    "lasted {s}s": ("durou {s}s", "a duré {s}s", "dauerte {s}s"),
    "on now": ("ativo agora", "actif", "gerade aktiv"),
    "refreshed": ("renovado", "renouvelé", "erneuert"),
    "No effects active right now": ("Nenhum efeito ativo agora", "Aucun effet actif", "Gerade keine Effekte aktiv"),
    "No effects yet": ("Nenhum efeito ainda", "Aucun effet pour l'instant", "Noch keine Effekte"),
    "Choose effects ▾": ("Escolher efeitos ▾", "Choisir des effets ▾", "Effekte wählen ▾"),
    "Choose effects ▴": ("Escolher efeitos ▴", "Choisir des effets ▴", "Effekte wählen ▴"),
    "Search": ("Buscar", "Rechercher", "Suchen"),
    "No effects found": ("Nenhum efeito encontrado", "Aucun effet trouvé", "Keine Effekte gefunden"),
    "{n} effects": ("{n} efeitos", "{n} effets", "{n} Effekte"),
    "{n} watched": ("{n} acompanhados", "{n} suivis", "{n} beobachtet"),
    "Hover an icon to see its name; click it to watch that effect (★).": (
        "Passe o mouse num ícone para ver o nome; clique para acompanhar o efeito (★).",
        "Survolez une icône pour voir son nom ; cliquez pour suivre l'effet (★).",
        "Fahre über ein Symbol für seinen Namen; klicke, um den Effekt zu beobachten (★)."),
    "Open my details when a fight starts": ("Abrir meus detalhes quando uma luta começar",
                                            "Ouvrir mes détails au début d'un combat",
                                            "Meine Details bei Kampfbeginn öffnen"),
    "Effects on {p}": ("Efeitos em {p}", "Effets sur {p}", "Effekte auf {p}"),
    "Effects {p} applied": ("Efeitos aplicados por {p}", "Effets appliqués par {p}", "Effekte von {p}"),
    "CASTS": ("USOS", "LANCERS", "EINSÄTZE"),
    "TIME": ("TEMPO", "TEMPS", "ZEIT"),
    "CASTS/MIN": ("USOS/MIN", "LANCERS/MIN", "EINSÄTZE/MIN"),
    "no damage": ("sem dano", "aucun dégât", "kein Schaden"),
    "Skill rotation": ("Rotação de skills", "Rotation de compétences", "Skill-Rotation"),
    "No skills cast yet": ("Nenhuma skill usada ainda", "Aucune compétence lancée", "Noch keine Skills benutzt"),
    "Tag": ("Troca", "Relais", "Wechsel"),
    "Dodge": ("Esquiva", "Esquive", "Ausweichen"),
    "Air dodge": ("Esquiva aérea", "Esquive aérienne", "Luftausweichen"),
    "Perfect dodge": ("Esquiva perfeita", "Esquive parfaite", "Perfektes Ausweichen"),
    # Cfg > Windows, the windows' wrench menus
    "Windows": ("Janelas", "Fenêtres", "Fenster"),
    "Watch bar": ("Barra de acompanhamento", "Barre de suivi", "Beobachtungsleiste"),
    "Guild boss score": ("Pontos do chefe da guilda", "Score du boss de guilde", "Gildenboss-Punkte"),
    "Open a window to place it before a fight. While this tab is open, the watch bar shows even when "
    "empty, so you can drag it into place.": (
        "Abra uma janela para posicioná-la antes de uma luta. Com esta aba aberta, a barra de "
        "acompanhamento aparece mesmo vazia, para você arrastá-la até o lugar.",
        "Ouvrez une fenêtre pour la placer avant un combat. Tant que cet onglet est ouvert, la barre "
        "de suivi s'affiche même vide, pour que vous puissiez la déplacer.",
        "Öffne ein Fenster, um es vor einem Kampf zu platzieren. Solange dieser Reiter offen ist, wird "
        "die Beobachtungsleiste auch leer angezeigt, damit du sie verschieben kannst."),
    "shows during a guild boss run": ("aparece durante uma partida do chefe da guilda",
                                      "s'affiche pendant une partie du boss de guilde",
                                      "erscheint während eines Gildenboss-Laufs"),
    "Compact view (only the icons)": ("Vista compacta (só os ícones)", "Vue compacte (icônes seulement)",
                                      "Kompakte Ansicht (nur Symbole)"),
    "Show the watch bar (watched effects, a boss's ultimate countdown)": (
        "Mostrar a barra de acompanhamento (efeitos acompanhados, contagem do ultimate de um chefe)",
        "Afficher la barre de suivi (effets suivis, compte à rebours de l'ultime d'un boss)",
        "Beobachtungsleiste zeigen (beobachtete Effekte, Countdown zum Ultimate eines Bosses)"),
})


def tutorial_step(i):
    """(title, text) of tutorial step i in the current language."""
    return (TUTORIAL_TR.get(_lang[0]) or TUTORIAL)[i]


def set_lang(lang):
    _lang[0] = lang if lang in LANGS else "en"


def tr(text, **kw):
    """text in the current language (English if it has no translation), with
    {placeholders} filled in from kw."""
    out = text if _lang[0] == "en" else TR.get(text, (text,) * 3)[LANGS.index(_lang[0]) - 1]
    return out.format(**kw) if kw else out


class Stats:
    """Damage done, broken down by skill. Used for a whole actor and for each hero."""

    def __init__(self):
        self.done = 0
        self.hits = 0
        self.crits = 0
        self.skills = collections.Counter()
        self.skill_hits = collections.Counter()
        self.skill_over = collections.Counter()   # damage beyond what was needed to kill
        self.max_hit = 0

    def add(self, skill, h):
        self.done += h["damage"]
        self.hits += h["multi"]
        self.crits += h["crit"] * h["multi"]
        self.skills[skill] += h["damage"]
        self.skill_hits[skill] += h["multi"]
        self.max_hit = max(self.max_hit, h["damage"] // h["multi"])

    def sub(self, dur):
        crit = 100 * self.crits / max(1, self.hits)
        return f"{self.done / max(dur, 1):,.0f}/s  {tr('crit')} {crit:.0f}%  {tr('max')} {self.max_hit:,}"


class Actor(Stats):
    def __init__(self):
        super().__init__()
        self.taken = 0
        self.heal = 0
        self.heroes = collections.defaultdict(Stats)   # hero name -> that hero's share
        self.combo_partner = {}                        # hero_weapon -> the other hero in its combo
        self.combo_recent = []                         # (time, hero_weapon) of recent combo hits
        self.targets = {}                              # enemy id -> Actor: damage done to it only
        self.bins = collections.Counter()              # whole second -> damage dealt in it (graph)


def stats_dict(st):
    return dict(done=st.done, hits=st.hits, crits=st.crits, max_hit=st.max_hit, skills=dict(st.skills),
                skill_hits=dict(st.skill_hits), skill_over=dict(st.skill_over))


def stats_load(st, d):
    st.done, st.hits, st.crits, st.max_hit = d["done"], d["hits"], d["crits"], d["max_hit"]
    for k in ("skills", "skill_hits", "skill_over"):
        getattr(st, k).update(d.get(k, {}))
    return st


def actor_dict(a):
    """An Actor as JSON (fight history)."""
    d = stats_dict(a)
    d.update(taken=a.taken, heal=a.heal, heroes={h: stats_dict(st) for h, st in a.heroes.items()},
             combo_partner=a.combo_partner, targets={str(k): actor_dict(v) for k, v in a.targets.items()},
             bins={str(k): v for k, v in a.bins.items()})
    return d


def actor_load(d):
    a = stats_load(Actor(), d)
    a.taken, a.heal, a.combo_partner = d.get("taken", 0), d.get("heal", 0), d.get("combo_partner", {})
    for h, hd in d.get("heroes", {}).items():
        stats_load(a.heroes[h], hd)
    a.targets = {int(k): actor_load(v) for k, v in d.get("targets", {}).items()}
    a.bins.update({int(k): v for k, v in d.get("bins", {}).items()})
    return a


DEFAULT_VIEW = {
    "me": {"heroes": True, "skills": False},        # detail panel: your character (skills: its size button)
    "others": {"heroes": True, "skills": False},    # detail panel: teammates
    "max_rows": 30,                                 # detail rows drawn in the overlay
    "icon_size": "medium",                          # SIZE_NAMES
    "font_size": "medium",
    "enemy_hp": True,                               # enemy HP bars at the top
    "max_enemies": 5,                               # enemy bars shown at once
    "auto_reset": 60,                               # s idle (party deals / takes no damage) before
                                                    # the fight is saved and cleared (0 = off)
    "opacity": 88,                                  # overlay opacity, percent
    "show_all": False,                              # monsters in damage taken
    "exact": False,                                 # 4,820,000 instead of 4.82M
    "bar_details": True,                            # main window: the line under each bar (DPS, crit,
                                                    # max hit; enemy HP); off = one-line, thinner bars
    "player_names": True,                           # players' character names instead of Player 2, ...
    "lang": "en",                                   # LANGS
    "start_locked": False,                          # start click-through instead of unlocked
    "tutorial_seen": False,                         # first start: greet and offer the tutorial
    "iface": "all",                                 # capture adapter: "all" or its friendly name
    "rot_small": False,                             # skill rotation window: icons only
    "watch": [],                                    # effects on the watch bar (Meter.effect_info keys)
    "sizes": {},                                    # window -> [w, h] it was resized to (absent: own size)
    "auto_detail": True,                            # a new fight opens your detail panel
    "fx_hidden": False,                             # Effects window: also the game's internal effects
    "boss_mode": True,                              # a boss kill ends the fight and saves it
    "watch_bar": True,                              # the watch bar (Cfg > Windows, Effects wrench)
    "gb_score": False,                              # the guild boss score window (Cfg > Windows)
}
# accessibility presets (Cfg > Display); build_assets.py renders icons/<preset>/ per icon size
SIZE_NAMES = ("mini", "small", "medium", "big", "giant")
ICON_SIZES = {"mini": 16, "small": 20, "medium": 28, "big": 36, "giant": 48}
FONT_SIZES = {"mini": 8, "small": 9, "medium": 11, "big": 12, "giant": 15}
ICON_DIR = os.path.join(ROOT, "icons", "medium")


def set_icon_size(preset):
    global ICON_DIR
    ICON_DIR = os.path.join(ROOT, "icons", preset if preset in ICON_SIZES else "medium")


def _load_slots():
    """skill_slots.json is made by build_assets.py from the game files."""
    try:
        with open(os.path.join(ROOT, "skill_slots.json"), encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        d = {}
    roles = {p.lower(): {s.lower(): r for s, r in sl.items()} for p, sl in d.get("roles", {}).items()}
    gear = {p: {c.lower(): n for c, n in codes.items()} for p, codes in d.get("gear_passives", {}).items()}
    gear["epset"] = {k.lower(): v for k, v in d.get("equip_sets", {}).items()}
    return (roles, {p.lower() for p in d.get("ultimate_is_r", [])}, {h.lower() for h in d.get("heroes", [])},
            gear, {k.lower(): v for k, v in d.get("pets", {}).items()},
            {k.lower(): v for k, v in d.get("changed_skills", {}).items()})


# ROLES: 'tristan_sworddual' -> {'skill_e': 'normal', 'skill_rmb': 'third', 'skill_q': 'special', ...}
# from the game's DefaultSkillWeaponTypeTable. Heroes missing from it fall back to the
# naming scheme: ULT_IS_R sets use skill_q = Q / skill_r = ultimate, others skill_rmb / skill_q.
# CHANGED: skills a buff turns another skill into -> the role of the slot they take over, e.g.
# Lancelot sword1h's charged Q: 'lancelot_sword1h_skill_q_atk1' -> 'attack' (ChangeSkillList)
ROLES, ULT_IS_R, HEROES, GEAR, PETS, CHANGED = _load_slots()
EQUIP_SETS = GEAR["epset"]
# gear passive prefix in damage skill names -> what it is
GEAR_KINDS = {"epwp": "Weapon", "epeq": "Gear", "eplb": "Limit break", "epar": "Armor",
              "epacc": "Accessory", "epset": "Set"}
HERO_ALIASES = {"gilthunder": "gil"}          # charge attacks use the hero name without "_"
DOT_NAMES = {"burn": "Burn", "bleeding": "Bleed", "bleed": "Bleed", "poison": "Poison", "poisoning": "Poison",
             "thundershock": "Shock", "electshock": "Shock", "curse": "Curse", "corrosion": "Corrosion",
             "freeze": "Freeze", "frostbite": "Frostbite"}


def _load_monster_names():
    try:
        with open(os.path.join(ROOT, "monster_names.json"), encoding="utf-8") as f:
            d = json.load(f)
        return ({int(k): v for k, v in d.get("actors", {}).items()},
                {k.lower(): v for k, v in d.get("names", {}).items()})
    except (OSError, ValueError, KeyError, AttributeError):
        return {}, {}


# from build_assets.py: ActorID -> name, spawn id -> name
MONSTER_ACTORS, MONSTER_NAMES = _load_monster_names()
# the guild boss's ultimate puts up five crystals, one per element: ActorID -> element, from a
# capture where each was hit in turn (fire, earth, wind, thunder, ice); not in the game's name table
GUILD_CRYSTALS = {50700102: "Fire", 50700103: "Ice", 50700104: "Thunder", 50700105: "Wind", 50700106: "Earth"}


def _load_buff_names():
    """buff_names.json (build_assets.py): {language: {buff id: in-game name}}."""
    try:
        with open(os.path.join(ROOT, "buff_names.json"), encoding="utf-8") as f:
            d = json.load(f)
        return {lang: {int(t): n for t, n in v.items()} for lang, v in d.items() if isinstance(v, dict)}
    except (OSError, ValueError, AttributeError):
        return {}


BUFF_NAMES = _load_buff_names()
BUFF_EN = BUFF_NAMES.get("en", {})
BUFF_ICONS = BUFF_NAMES.pop("icons", {})                         # buff id -> icons/<size>/buff_<this>.png


def buff_name(tid):
    """A buff's in-game name in the meter's language (English if it has none there)."""
    return BUFF_NAMES.get(_lang[0], {}).get(tid) or BUFF_EN.get(tid)


def buff_key(tid):
    """What makes two named buffs the same effect: their English name and their icon.
    Levels and re-applications share both; different effects can share a name (Elaine's
    three "Saintess's Mark": tag gauge, Earth Burst resistance down, Earth damage up)."""
    icon = BUFF_ICONS.get(tid)
    return f"{BUFF_EN[tid]} [{icon}]" if icon else BUFF_EN[tid]


def parse_spawn(body):
    """P2C spawn message (10021) -> (actor id, spawn id, ActorID, HP, owner), or None.
    Layout (reverse engineered): actor id, 25 fixed bytes, spawn id string (a summon has
    a number there), u32 ActorID (MonsterActorTable row), 12 bytes, u16 count + count x
    u32, then the HP (int64): the full HP when it spawns, without shields. A player's
    summon (pets, clones, Daisy's lasers, ...) has the player's actor id 103 bytes after
    the HP (-1 for the boss's own objects); owner is None for anything else."""
    r = Reader(body)
    actor = r.u("q")
    r.i = 33
    tid = r.wstr()
    if not tid or len(tid) > 128 or not all(32 < ord(c) < 127 for c in tid):
        return None
    table_id = r.u("I")
    r.i += 12
    count = r.u("H")
    if count > 256:
        return None
    r.i += 4 * count
    hp = r.u("q")
    owner = None
    if tid.isdigit() and r.i + 111 <= len(body):
        owner = struct.unpack_from(">q", body, r.i + 103)[0]
        owner = owner if owner > 0 else None
    return (actor, tid, table_id, hp, owner) if 0 < hp < 10 ** 13 else None


def parse_roster(body):
    """The dungeon's player list (10140, 'DungeonMatch', sent when the dungeon loads and
    when someone joins) -> {actor id: character name}. Each player's record holds
    u64 account, u32, u64 actor id, u64 account again, then the name (u16 length +
    UTF-16): the account on both sides of the actor id is what finds a record, the
    rest (gear, skills) is skipped."""
    out = {}
    for i in range(12, len(body) - 18):
        acct = body[i + 8:i + 16]
        if acct != body[i - 12:i - 4] or acct == bytes(8):
            continue
        n = struct.unpack_from(">H", body, i + 16)[0]
        if not (2 <= n <= 64 and n % 2 == 0) or i + 18 + n > len(body):
            continue
        try:
            name = body[i + 18:i + 18 + n].decode("utf-16le")
        except UnicodeDecodeError:
            continue
        if name.isprintable():
            out[struct.unpack_from(">q", body, i)[0]] = name
    return out


def parse_property(body):
    """P2C_ReportProperty (10062): actor id, i16, value (clamped at 0), raw value, type."""
    actor, _, value, raw, typ = struct.unpack_from(">qhqqh", body)
    return actor, typ, value, raw
ROLE_NAMES = {"attack": "Normal attack", "aerial": "Jump attack", "normal": "E", "third": "Q",
              "special": "Ultimate", "tag": "Tag", "passive": "Passive", "rmb": "Special", "combo": "Combo"}
FALLBACK_ROLES = {"normalatk": "attack", "jumpatk": "aerial", "skill_e": "normal", "skill_tag": "tag",
                  "skillpassive": "passive", "skill_passive": "passive", "ultimateskill": "special",
                  "combineskill": "combo", "passive": "passive"}
# upgraded skills from hero grade: 'grade_7_merlin_staff_skill_e' is Merlin's E
GRADE_RE = re.compile(r"^grade_\d+_", re.I)
SLOT_RE = re.compile(r"_(normalatk|jumpatk|skillpassive|ultimateskill|combineskill|skill_[a-z0-9]+|passive)(?=_|$)", re.I)
BASE_PARTS = ("normalatk", "jumpatk")   # their numbered variants are the skill itself
ELEMENTS = ("fire", "ice", "wind", "thunder", "earth", "holy", "dark")


def split_skill(skill):
    """'tristan_sworddual_skill_q_bomb' -> ('tristan_sworddual', 'skill_q', '_bomb');
    (None, None, None) when there is no known slot in the name."""
    skill = GRADE_RE.sub("", skill)
    m = SLOT_RE.search(skill)
    if not m:
        return None, None, None
    return skill[:m.start()].lower(), m.group(1).lower(), skill[m.end():]


def special_key(skill):
    """Skills not tied to a hero: gear set bonuses ('epset_ab_attack_lv1' -> 'epset_ab'),
    elemental bursts ('fire_burstactivation_dmg' -> 'fire_burst') and team combos
    ('combine_thunder_ground_dmg' -> 'combine_thunder')."""
    low = GRADE_RE.sub("", skill.lower())
    p = low.split("_")
    if p[0] in GEAR_KINDS:                       # gear passive: 'epwp_hellfire_lv7' -> 'epwp_hellfire'
        rest = low[len(p[0]) + 1:]
        codes = [c for c in GEAR.get(p[0], {}) if rest == c or rest.startswith(c + "_")]
        return f"{p[0]}_" + (max(codes, key=len) if codes else rest.split("_")[0])
    if "tickdam" in p:                           # damage over time: 'common_tickdam_burn', 'tickdam_fire_b_..'
        after = p[p.index("tickdam") + 1:]
        kind = next((x for x in after + p if x in DOT_NAMES or x in ELEMENTS), None)
        return "dot_" + (kind or "other")
    if p[0] == "sadebuff":                       # status ailment damage: 'sadebuff_burn01_1'
        return "status_" + re.sub(r"\d+$", "", p[1]) if len(p) > 1 else "status_other"
    if low.startswith("just_avoidanceskill"):
        return "perfect_dodge"
    if p[0] == "pet" and len(p) > 1:
        rest = low[4:]
        codes = [c for c in PETS if rest == c or rest.startswith(c + "_")]
        return "pet_" + (max(codes, key=len) if codes else p[1])
    if p[0] in ("transform", "skill") and len(p) > 1:   # 'transform_hawk_..', 'skill_usefood_..'
        return f"{p[0]}_{p[1]}"
    charge = next((x for x in p if re.fullmatch(r"charge\d*", x)), None)
    if charge and HERO_ALIASES.get(p[0], p[0]) in HEROES and not SLOT_RE.search(low):
        return "charge_" + HERO_ALIASES.get(p[0], p[0])
    if len(p) > 1 and p[0] in ELEMENTS and p[1].startswith("burstactivation"):
        return p[0] + "_burst"
    if "combine" in p:                          # elemental combination ('dark_combine_thunder_...')
        return "_".join(["combine"] + [e for e in p if e in ELEMENTS])
    if len(p) > 1 and p[0] in ELEMENTS:          # element field effect: 'wind_twister_ground_dmg'
        return f"element_{p[0]}_{p[1]}"
    return None


@functools.lru_cache(maxsize=4096)
def changed_key(skill):
    """The changed skill a damage skill name belongs to ('lancelot_sword1h_skill_q_atk2_ground_dmg'
    -> 'lancelot_sword1h_skill_q_atk2'), or None."""
    low = GRADE_RE.sub("", skill.lower())
    return max((c for c in CHANGED if low == c or low.startswith(c + "_")), key=len, default=None)


def skill_key(skill):
    """One row per skill: normal attack variants and the parts of a skill
    ('..._skill_q_bomb', '..._skill_q_fire') add up under '..._skill_q'. Enchanted
    versions ('calla_sworddual_skill_q_enchant_hitchange') get their own row,
    '..._skill_q_enchant', since the game shows them with their own icon."""
    special = special_key(skill) or changed_key(skill)
    if special:
        return special
    prefix, slot, part = split_skill(skill)
    if not slot:
        return skill
    return f"{prefix}_{slot}" + ("_enchant" if "_enchant" in part.lower() else "")


def skill_role(key):
    """(hero_weapon prefix, role, enchanted) for a skill key; role None if unknown."""
    prefix, slot, part = split_skill(key)
    if not slot:
        return None, None, False
    enchant = "_enchant" in part.lower()
    if key in CHANGED:                          # evolved skill: the role of the slot it takes over
        return prefix, CHANGED[key], False
    role = ROLES.get(prefix, {}).get(slot) or FALLBACK_ROLES.get(slot)
    if not role:
        if prefix in ULT_IS_R:
            role = {"skill_q": "third", "skill_r": "special", "skill_rmb": "rmb"}.get(slot)
        else:
            role = {"skill_rmb": "third", "skill_q": "special"}.get(slot)
    return prefix, role, enchant


def skill_label(key, with_hero=True):
    """'tristan_sworddual_skill_q' -> 'Ultimate' (or 'Tristan Ultimate')."""
    if key.endswith("_burst") and key[:-6] in ELEMENTS:
        return tr("{e} burst", e=tr(key[:-6].capitalize()))
    pre, _, code = key.partition("_")
    if pre in GEAR_KINDS:
        return f"{tr(GEAR_KINDS[pre])}: " + GEAR.get(pre, {}).get(code, code.replace("_", " "))
    if pre == "dot":
        if code in DOT_NAMES:
            return tr("{x} (DoT)", x=tr(DOT_NAMES[code]))
        return tr("{e} DoT", e=tr(code.capitalize())) if code in ELEMENTS else "DoT"
    if pre == "status":
        return tr(DOT_NAMES.get(code, code.capitalize()))
    if key == "perfect_dodge":
        return tr("Perfect dodge counter")
    if pre == "pet":
        return tr("Pet: {x}", x=PETS.get(code, code.replace("_", " ").capitalize()))
    if pre == "transform":
        return tr("Transform: {x}", x=code.capitalize())
    if key == "skill_usefood":
        return tr("Food")
    if pre == "charge":
        return tr("Charge attack")
    if pre == "element":
        e, _, what = code.partition("_")
        return f"{tr(e.capitalize())} {what}"
    if key == "combine" or key.startswith("combine_"):
        elems = key.split("_")[1:]
        return tr("{e} combo", e=" + ".join(tr(e.capitalize()) for e in elems)) if elems else tr("Combo")
    prefix, role, enchant = skill_role(key)
    if not prefix:
        return key
    if role:
        name = tr(ROLE_NAMES[role])
    else:
        slot = split_skill(key)[1]
        rest = slot[6:] if slot.startswith("skill_") else slot
        name = rest.upper() if len(rest) == 1 else rest.replace("_", " ").capitalize()
    if enchant:
        name += tr(" (enchanted)")
    elif key in CHANGED:
        name += tr(" (evolved)")
    if with_hero:
        name = prefix.split("_", 1)[0].capitalize() + " " + name
    return name


def _icon(name):
    path = os.path.join(ICON_DIR, name + ".png")
    return path if os.path.exists(path) else None


def skill_icon(key):
    """Icon file for a skill key (from build_assets.py), or None: the hero's own skill
    icons, the weapon's normal attack icon, the shared tag icon, burst icons."""
    if key.endswith("_burst") and key[:-6] in ELEMENTS:
        return _icon("burst_" + key[:-6])
    prefix, role, enchant = skill_role(key)
    if not prefix or not role:
        return None
    if key in CHANGED:                          # the game's own icon, else the slot's enchanted one
        changed = _icon("changed_" + key) or _icon(f"{prefix}_{role}_enchant")
        if changed:
            return changed
    if role in ("attack", "aerial"):
        return _icon("attack_" + prefix.rsplit("_", 1)[-1])
    if role == "tag":
        return _icon("tag")
    if role == "combo":                         # shown with the hero's ultimate icon
        return _icon(f"{prefix}_special")
    return (enchant and _icon(f"{prefix}_{role}_enchant")) or _icon(f"{prefix}_{role}")


def hero_icon(hero):
    return _icon("hero_" + hero.lower())


def skill_rows(st, level, hero=None, partners=None):
    """Skill rows; a combo row also gets its partner hero's ultimate icon (icon2)."""
    rows = []
    for sk, v in st.skills.most_common():
        n = st.skill_hits[sk]
        prefix, role, _ = skill_role(sk)
        partner = (partners or {}).get(prefix) if role == "combo" else None
        rows.append(dict(level=level, label=skill_label(sk, with_hero=not hero), value=v, parent=st.done,
                         sub=f"{n} hits  avg {v // max(1, n):,}" + (
                             f"  overdamage -{st.skill_over[sk]:,}" if st.skill_over[sk] else ""),
                         over=st.skill_over[sk], hits=n, key=sk, icon=skill_icon(sk),
                         icon2=_icon(f"{partner}_special") if partner else None,
                         tag="combo" if role == "combo" else None))
    # same hero with two weapons: 'Ultimate (sworddual)' / 'Ultimate (sword1h)'
    counts = collections.Counter(r["label"] for r in rows)
    for r in rows:
        prefix = split_skill(r["key"])[0]
        if counts[r["label"]] > 1 and prefix and "_" in prefix:
            r["label"] += f" ({prefix.split('_', 1)[1]})"
    return rows


def detail_rows(a, view, dur, partners=None):
    """Hero and/or skill rows for one player's detail panel, per the view config."""
    partners = a.combo_partner if partners is None else partners
    rows = []
    if view["heroes"] and set(a.heroes) - {"Other"}:     # monsters have no heroes
        for hero, hs in sorted(a.heroes.items(), key=lambda kv: -kv[1].done):
            if hs.done <= 0:
                continue
            rows.append(dict(level=1, label=hero, value=hs.done, parent=a.done, sub=hs.sub(dur),
                             icon=hero_icon(hero)))
            if view["skills"]:
                rows += skill_rows(hs, 2, hero, partners)
    elif view["skills"]:
        rows += skill_rows(a, 1, partners=partners)
    return rows


ROTATION_MAX = 500                               # casts kept for the rotation
ROTATION_CHAIN = 3.0                             # s: the same skill again within this adds to its chip
DODGES = {"avoidanceskill": "Dodge", "airavoidanceskill": "Air dodge", "justavoidanceskill": "Perfect dodge"}


def cast_info(skill):
    """(key, hero, label) of one of your cast requests. Besides the hero skills
    there are dodges ('merlin_common_avoidanceskill', ..._airavoidanceskill,
    ..._justavoidanceskill) and the tag swap ('cotag01', hero None: the next cast's)."""
    low = GRADE_RE.sub("", skill.lower())
    if low.startswith("cotag"):
        return "tag", None, tr("Tag")
    hero, _, kind = low.partition("_common_")
    if kind in DODGES:
        return "dodge_" + kind, hero.capitalize(), tr(DODGES[kind])
    key = skill_key(skill)
    return key, hero_name(skill), skill_label(key, with_hero=False)


# the game's default keys (Table/Input/InputKeyMappingTable), shown in the rotation: normal (and
# jump) attack LMB, E heronormalskill, Q herospecialskill, the ultimate herospecialskilltomagicforce
# R, herothirdactiveskill RMB, dodge heroavoidance Left Shift, tag-in skills 1-4
CAST_KEYS = {"attack": "LMB", "aerial": "LMB", "normal": "E", "third": "Q", "special": "R", "rmb": "RMB",
             "tag": "1-4"}


def cast_bind(key):
    """The key a cast was (by default) pressed with, or None."""
    if key == "tag":
        return CAST_KEYS["tag"]
    if key and key.startswith("dodge_"):
        return "Shift"
    return CAST_KEYS.get(skill_role(key)[1]) if key else None


def rotation_groups(casts, start=None):
    """Your casts (dicts from Meter.feed, with the damage link_cast gave them) as
    rotation entries, in order: dict(t (s since start), gap (s since the previous
    cast), key, label, icon, hero, n, damage, hits, crits, swap). A normal attack
    chain (1..4) and repeated dodges within ROTATION_CHAIN s are one entry with n
    casts; a tag swap's entry gets the portrait of the hero swapped in."""
    if not casts:
        return []
    start = casts[0]["t"] if start is None else start
    groups, prev = [], None
    for c in casts:
        t, sk = c["t"], c["skill"]
        key, h, label = cast_info(sk)
        gap = t - prev if prev is not None else None
        prev = t
        last = groups[-1] if groups else None
        stats = dict(damage=c["damage"], hits=c["hits"], crits=c["crits"])
        if skill_role(key)[1] == "tag":           # the hero's own tag skill: a swap to that hero
            if last and last["key"] == "tag" and not last["hero"]:
                last["key"] = None                # 'cotag01' right before it: the same swap
                last.update(hero=h, icon=hero_icon(h) or last["icon"], label=f"{tr('Tag')} {h}")
                for k, v in stats.items():
                    last[k] += v
                continue
            groups.append(dict(t=max(0.0, t - start), gap=gap, t_last=t, key=key, label=f"{tr('Tag')} {h}",
                               icon=hero_icon(h) or skill_icon(key), hero=h, n=1, swap=True,
                               bind=CAST_KEYS["tag"], **stats))
            continue
        if h:
            for g in reversed(groups):            # tags before this cast swapped this hero in
                if g["key"] != "tag" or g["hero"]:
                    break
                g.update(hero=h, icon=hero_icon(h) or g["icon"], label=f"{tr('Tag')} {h}")
        chain = key.startswith("dodge_") or skill_role(key)[1] in ("attack", "aerial")
        if chain and last and last["key"] == key and t - last["t_last"] < ROTATION_CHAIN:
            last["n"] += 1
            last["t_last"] = t
            for k, v in stats.items():
                last[k] += v
            continue
        icon = _icon("tag") if key == "tag" else None if key.startswith("dodge_") else skill_icon(key)
        groups.append(dict(t=max(0.0, t - start), gap=gap, t_last=t, key=key, label=label, icon=icon,
                           hero=h if key != "tag" else None, n=1, swap=key == "tag", bind=cast_bind(key), **stats))
    return groups


FIGHT_FORMAT = "sds-meter-fight"                # fight history / export files
# bosses with a mechanic of their own, by a piece of their spawn id. The guild boss
# (Demonic Beast Akumu): at 1 HP it is "killed", comes back with full, higher HP and a
# level more (up to 30; after that a kill only refills it), and its ultimate: it puts
# ult_start on itself, charges, and ult_hit lands `charge` s later (measured: 31.4 s;
# every ultimate the meter sees updates it). prefix: its skills' names, to know it
# also when the meter missed its spawn. score: the guild ranking's points per damage dealt to
# it (Table/Dungeon/BossStatGroupTable: Bonus_Ratio 0.0001 and Bonus_Score 0 at all 30 levels).
# scores: the server's score on reaching each level, the same in every run (it scores HP
# removed, so each life is worth its HP times score); the meter learns the rest (BOSS_SCORES_FILE).
BOSS_PROFILES = {
    "acumu_demon": dict(prefix="51300084_", levels=30, charge=31.4, score=0.0001,
                        ult_start="51300084_skill_1_start", ult_hit="51300084_skill_1_end",
                        scores={2: 209, 3: 501, 4: 898, 5: 1416, 6: 2071, 7: 2890, 8: 3910, 9: 5151,
                                10: 6636, 11: 8406, 12: 10808}),
}
BOSS_SCORES_FILE = os.path.join(USER, "boss_scores.json")      # level scores learned from the server
# the guild boss's score: at each level-up the server sends the level and the score so far
# (u32, u64), and when the run ends a result with the final score as its second u64
MSG_BOSS_SCORE, MSG_BOSS_RESULT = 11293, 11429
BOSS_GRACE = 5.0                                # s after a boss kill that still belong to that fight
HISTORY_MAX = 300                               # fight files kept


class Meter:
    show_names = True                          # Cfg: players' character names instead of Player 2, ...

    def __init__(self, log=True):
        self.lock = threading.Lock()
        self.key = KeyLearner()
        self.streams = collections.defaultdict(Stream)
        self.pending_impacts = collections.deque(maxlen=5000)  # (t, raw) seen before key known
        self.my_skills = {}                                     # skill -> last time used
        self.me = set()
        self.names = {}                                         # actor id -> hero name
        self.current_hero = {}                                  # actor id -> hero last seen
        self.players = set()
        self.player_order = []                                  # players in order of first appearance
        self.prefix_actor = {}                                  # 'tristan_sworddual' -> actor using it
        self.main_actors = set()                                # actors seen using a skill directly
        self.owner = {}                                         # skill object actor -> its hero
        self.spawn_owner = {}                                   # summon actor -> player, from its spawn
        self.roster = {}                                        # player actor -> character name (10140)
        self.roster_t = 0.0                                     # capture time of the last list
        self.boss_ids = set()                                   # actors whose spawn id says boss
        self.boss_profile = {}                                  # boss actor -> its BOSS_PROFILES key
        self.ult_charge = {k: v["charge"] for k, v in BOSS_PROFILES.items()}   # learned charge times
        self.level_scores = {k: dict(v.get("scores", {})) for k, v in BOSS_PROFILES.items()}
        try:
            with open(BOSS_SCORES_FILE, encoding="utf-8") as f:
                for k, v in json.load(f).items():
                    if k in self.level_scores:
                        self.level_scores[k].update({int(lv): s for lv, s in v.items()})
        except (OSError, ValueError, AttributeError, TypeError):
            pass
        self.boss_mode = True                                   # a boss kill ends (and saves) the fight
        self.buff_offset = None                                 # capture time - server time (s)
        self.history_dir = None                                 # where finished fights are saved
        self.saved = None                                       # path of the last fight saved
        self.loaded = None                                      # a fight loaded from a file: its data
        self.buff_ver = 0                                       # changes when an effect does
        self.last_t = 0.0                                       # capture time of the last packet
        self.reset()
        self.packets = 0
        self.impacts = 0
        self.last_packet = 0.0
        self.first_packet = 0.0
        self.s2c_packets = 0                                    # 0 with outgoing ones: firewall
        self.ports = DEFAULT_PORTS
        self.auto_reset = 0                                     # s idle before a reset (0 = manual only)
        self.last_damage_wall = 0.0                             # wall clock of the party's last damage
        self.last_active = None                                 # capture time of it
        self.server = None                                      # "ip:port" of the game server
        self.my_heroes = set()                                  # hero ids in your cast requests
        self.ability_msgs = collections.deque(maxlen=64)        # (t, raw) 10100 stat sheets
        self.me_actor = None                                    # your actor id, from them
        self.spawns = {}                                        # actor id -> (name, HP at spawn)
        self.msg_hp = {}                                        # target -> lowest HP in this message
        self.rejected = 0
        self.seen_ids = set()
        self.debug = None
        if log:
            try:
                self.debug = open(DEBUG_LOG, "w", encoding="utf-8")
            except OSError:
                pass

    def log(self, t, text):
        """meter_debug.log: skills you cast, every hit, and every dropped hit with
        the reason, so damage that goes missing can be tracked down."""
        if self.debug is None:
            return
        try:
            if self.debug.tell() > DEBUG_LOG_MAX:
                return
            self.debug.write(f"{t:.3f} {text}\n")
            self.debug.flush()
        except (OSError, ValueError):
            pass

    def check_idle(self):
        """Auto reset on the clock too, not only when the next hit arrives: after
        auto_reset s in which the party dealt and took no damage, the fight is saved to
        the history (reset -> finish_fight) and the live meter cleared."""
        with self.lock:
            if self.auto_reset and self.t1 is not None and self.last_active is not None and \
                    time.time() - self.last_damage_wall > self.auto_reset:
                self.reset()
                return True
        return False

    def reset(self, keep_after=None):
        """Saves the fight to the history (finish_fight), then clears it. keep_after: an
        auto reset on the next fight's first hit keeps the casts that opened that fight
        (cast after the last damage of the previous one)."""
        if getattr(self, "actors", None) is not None:
            self.finish_fight()
        old_buffs = getattr(self, "buffs", {})
        off = self.buff_offset or 0
        self.buffs = {k: b for k, b in old_buffs.items()            # still on: may count in the next fight
                      if keep_after is not None and b["end"] + off > keep_after}
        self.frozen = None                                      # boss mode: the time the last boss died
        self.ults = {b: dict(start=u["start"], hits=[]) for b, u in getattr(self, "ults", {}).items()
                     if u.get("start") is not None}             # boss -> ultimate charging / its hits
        self.boss_damage = 0                                    # party damage to profiled bosses (score)
        self.score_cp = None                                    # the server's last score: level, score, damage then
        self.score_final = None                                 # the run's final score (its result)
        self.actors = collections.defaultdict(Actor)
        self.enemies = {}                                       # target id -> HP tracking
        self.t0 = self.t1 = None
        old = getattr(self, "rotation", ())
        self.rotation = collections.deque((c for c in old if keep_after is not None and c["t"] > keep_after),
                                          maxlen=ROTATION_MAX)  # your casts, in order (see link_cast)
        self.cast_ids = {c["guid"]: c for c in self.rotation}
        self.rotation_ver = getattr(self, "rotation_ver", 0) + 1

    # ---- input
    def feed(self, t, src, sport, dst, dport, seq, payload, ports):
        with self.lock:
            self.packets += 1
            self.last_packet = time.time()
            self.last_t = t
            self.first_packet = self.first_packet or self.last_packet
            s2c = ports[0] <= sport <= ports[1]
            if s2c:
                self.server = f"{src}:{sport}"
                self.s2c_packets += 1
            st = self.streams[(src, sport, dst, dport)]
            st.feed(seq, payload, t)
            for m in st.messages():
                self.key.observe(m)
                mid = int.from_bytes(m[6:8], "big")
                if (s2c, mid) not in self.seen_ids:
                    self.seen_ids.add((s2c, mid))
                    self.log(t, f"first {'S2C' if s2c else 'C2S'} msg {mid} len {len(m)}")
                if mid in IMPACT_MSGS and s2c:
                    if not self.handle_impact(t, m):
                        self.pending_impacts.append((t, m))
                    elif self.pending_impacts:
                        self.replay_pending()
                elif mid == MSG_USE_SKILL and not s2c:
                    for T in self.key.tables():
                        try:
                            hero, guid, sk = parse_use_skill(decrypt(m, T))
                        except (struct.error, IndexError):
                            continue
                        if sk and all(32 < ord(c) < 127 for c in sk):
                            self.my_skills[sk] = t
                            c = dict(t=t, skill=sk, guid=guid, key=cast_info(sk)[0], damage=0, hits=0, crits=0)
                            if len(self.rotation) == self.rotation.maxlen:
                                self.cast_ids.pop(self.rotation[0]["guid"], None)
                            self.rotation.append(c)
                            self.cast_ids[guid] = c
                            self.rotation_ver += 1
                            self.log(t, f"cast {sk} (hero {hero})")
                            if hero not in self.my_heroes:
                                self.my_heroes.add(hero)
                                self.identify_me(t)
                            prefix = split_skill(sk)[0]
                            if prefix and self.me:
                                self.prefix_actor[prefix] = self.me_actor or min(self.me)
                            break
                elif mid == MSG_SPAWN and s2c:
                    for T in self.key.tables():
                        try:
                            res = parse_spawn(decrypt(m, T))
                        except (struct.error, IndexError):
                            continue
                        if res:
                            actor, tid, table_id, hp, owner = res
                            name = MONSTER_ACTORS.get(table_id) or MONSTER_NAMES.get(tid.lower())
                            if not name and table_id in GUILD_CRYSTALS:
                                name = tr("{e} crystal", e=tr(GUILD_CRYSTALS[table_id]))
                            self.spawns[actor] = (name, hp)
                            if owner is not None:
                                self.spawn_owner[actor] = owner
                                self.log(t, f"spawn {actor} is a summon of {owner}")
                            if "boss" in tid.lower():
                                self.boss_ids.add(actor)
                            prof = next((k for k in BOSS_PROFILES if k in tid.lower()), None)
                            if prof:
                                self.boss_profile[actor] = prof
                            if name:
                                self.log(t, f"spawn {actor} {tid} ({table_id}) = {name}, HP {hp:,}")
                            break
                elif mid == MSG_ROSTER and s2c:
                    for T in self.key.tables():
                        try:
                            found = parse_roster(decrypt(m, T))
                        except (struct.error, IndexError):
                            continue
                        if found:
                            self.set_roster(t, found)
                            break
                elif mid == MSG_PROPERTY and s2c and self.key.confirmed is not None:
                    try:
                        actor, typ, value, raw = parse_property(decrypt(m, self.key.confirmed))
                    except (struct.error, IndexError):
                        continue
                    e = self.enemies.get(actor)
                    if typ == PROP_HP and e is not None:
                        self.set_enemy_hp(e, value, t, authoritative=True)
                        if value <= 0:
                            self.exact_overdamage(e, max(0, -raw))
                elif mid == MSG_BUFFS and s2c and self.key.confirmed is not None:
                    try:
                        caster, target, items = parse_buffs(decrypt(m, self.key.confirmed))
                    except (BadImpact, struct.error, IndexError):
                        continue
                    self.add_buffs(t, caster, target, items)
                elif mid in (MSG_BOSS_SCORE, MSG_BOSS_RESULT) and s2c and self.key.confirmed is not None:
                    try:
                        b = decrypt(m, self.key.confirmed)
                        if mid == MSG_BOSS_SCORE:
                            level, score = struct.unpack_from(">IQ", b)
                            if level == 1 and self.boss_damage:
                                self.reset(keep_after=t)    # a new run: the last one is its own fight
                            # it comes right after the killing hits, before the refill and the next
                            # life's hits; resets: its refills so far, the next one starts this level.
                            # Level 1 (a run's start) comes before the new boss is hit: no refill
                            sb = self.score_boss()
                            resets = -1 if level == 1 else self.enemies[sb[0]].get("resets", 0) if sb else None
                            self.score_cp = dict(level=level, score=score, damage=self.boss_damage, resets=resets)
                            self.log(t, f"boss score {score} at level {level}")
                            self.learn_level_score(level, score)
                        else:
                            self.score_final = struct.unpack_from(">Q", b, 8)[0]
                            self.log(t, f"boss run result: score {self.score_final}")
                    except struct.error:
                        continue
                elif mid == MSG_BUFF_END and s2c and self.key.confirmed is not None:
                    try:
                        _target, inst = struct.unpack_from(">qq", decrypt(m, self.key.confirmed))
                    except struct.error:
                        continue
                    b = self.buffs.get(inst)
                    if b is not None and self.buff_offset is not None:
                        b["end"] = min(b["end"], t - self.buff_offset)
                        self.buff_ver += 1
                elif mid == MSG_ABILITY and s2c:
                    self.ability_msgs.append((t, m))
                    self.identify_me(t, newest=self.me_actor is not None)

    def identify_me(self, t, newest=False):
        """P2C_ReportAbility (stat sheets) is only sent for your own character:
        (actor id, hero id). The actor whose hero ids match the heroes in your own
        cast requests is you, also in a group where teammates play the same heroes.
        The newest sheet counts: a sheet for another actor id means you are in a new
        room (every room gives everyone new actor ids). newest: only the sheet that just
        came (you are known: the older ones were checked already)."""
        if not self.my_heroes:
            return
        for mt, m in list(reversed(self.ability_msgs))[:1 if newest else None]:
            for T in self.key.tables():
                b = decrypt(m, T)
                if len(b) < 16:
                    continue
                actor, hero = struct.unpack_from(">qq", b)
                if hero not in self.my_heroes:
                    continue
                if self.roster and actor not in self.roster and mt < self.roster_t:
                    return                              # a sheet from the room before this one
                if actor == self.me_actor:
                    return
                if self.me_actor is not None:
                    self.new_room(t, f"you are now actor {actor}")
                self.me_actor = actor
                wrong = self.me - {actor}
                self.me = {actor}
                self.log(t, f"you are actor {actor}" + (f" (not {sorted(wrong)})" if wrong else ""))
                return

    def new_room(self, t, why):
        """A new room (dungeon, raid, field) gives every player a new actor id: who is
        who is learned again, so the old ids don't add rows or push the numbers up
        (Player 6, Player 7 in a party of 5) and you are Me again. A fight you dealt
        damage in under your old id is saved and cleared; otherwise the fight is
        already the new room's (noticed after its first hits) and it is kept, with
        the players in it."""
        self.log(t, f"new room: {why}")
        if any(self.actors[a].done > 0 for a in self.me if a in self.actors):
            self.reset(keep_after=self.last_active)     # keeps the casts made since the last fight
        live = {a for a, x in self.actors.items() if x.done > 0}
        self.me, self.me_actor = set(), None
        self.players &= live
        self.player_order = [p for p in self.player_order if p in live]
        self.names = {a: n for a, n in self.names.items() if a in live}
        self.current_hero = {a: h for a, h in self.current_hero.items() if a in live}
        self.prefix_actor = {k: a for k, a in self.prefix_actor.items() if a in live}
        self.main_actors &= live
        self.roster = {}

    def replay_pending(self):
        old, self.pending_impacts = list(self.pending_impacts), collections.deque(maxlen=5000)
        for t, m in old:
            self.handle_impact(t, m)

    def handle_impact(self, t, m):
        mid = int.from_bytes(m[6:8], "big")
        body_len = int.from_bytes(m[17:19], "big")
        reasons = []
        for T in self.key.tables():
            try:
                if mid == MSG_IMPACT:
                    res = [parse_impact_strict(decrypt(m, T), body_len, check_flags=T != self.key.confirmed)]
                else:
                    if T != self.key.confirmed:     # only 10040 confirms a key
                        raise BadImpact("key not confirmed yet")
                    caster, hits = parse_object_impact(mid, decrypt(m, T), body_len)
                    by_skill = {}
                    for sk, h in hits:
                        by_skill.setdefault(sk, []).append(h)
                    res = [(caster, sk, hs) for sk, hs in by_skill.items()]
            except (BadImpact, struct.error, IndexError) as e:
                reasons.append(str(e))
                continue
            if mid == MSG_IMPACT:
                self.key.confirm(T)
            self.impacts += 1
            self.msg_hp, self.msg_alive, self.msg_kills = {}, {}, []
            for caster, skill, hits in res:
                self.record(t, caster, skill, hits)
            self.settle_kills()
            for target, (hp, dmg) in self.msg_hp.items():
                e = self.enemies.get(target)
                if e is not None:
                    self.set_enemy_hp(e, hp, t, damage=dmg)
            return True
        if self.key.confirmed is not None:     # key is known, so this is a real drop
            self.rejected += 1
            self.log(t, f"DROPPED impact {mid}: {' | '.join(reasons)} | "
                        f"{decrypt(m, self.key.confirmed).hex()}")
        return False

    def record(self, t, caster, skill, hits):
        caster = self.resolve_owner(t, caster, skill)
        name = hero_name(skill)
        if name:
            known = self.names.get(caster, '')
            if name not in known.split('/'):          # tag swaps keep the same actor id
                self.names[caster] = known + '/' + name if known else name
            if caster not in self.players:
                self.player_order.append(caster)
            self.players.add(caster)
            self.current_hero[caster] = name
        # numeric skill ids (summons, procs) go to whichever hero the actor was last
        hero = name or self.current_hero.get(caster) or "Other"
        # until a stat sheet identifies you: guess from the skills you cast (can also
        # match teammates playing the same hero, so identify_me replaces it)
        if self.me_actor is None and skill in self.my_skills and abs(t - self.my_skills[skill]) < 10:
            self.me.add(caster)
        key = skill_key(skill)
        self.boss_skill(t, caster, skill, hits)
        dealt = [h for h in hits if not h["no_damage"] and h["damage"] > 0]
        self.log(t, f"hit {caster} {skill} " + " ".join(
            f"[{h['target'] & 0xFFFFFF:06x} {h['damage']} x{h['multi']} f{''.join(map(str, h['flags']))}]"
            for h in hits))
        if not dealt:
            return
        damage = any(not h["heal"] for h in dealt)      # heals never start a new fight
        # the party is in it (dealing or taking damage): what keeps a fight from being idle
        party = bool(name) or caster in self.players or caster in self.me or \
            any(h["target"] in self.players or h["target"] in self.me for h in dealt)
        if damage and party and self.frozen is not None and t - self.frozen > BOSS_GRACE and \
                (name or caster in self.players or caster in self.me):
            self.reset(keep_after=self.frozen)          # boss mode: a player's next hit starts the next fight
        elif damage and party and self.auto_reset and self.last_active is not None and \
                t - self.last_active > self.auto_reset:
            self.reset(keep_after=self.last_active)     # idle too long: saved to the history, cleared
        if damage:                                      # the fight's time: damage only, heals don't stretch it
            self.t0 = t if self.t0 is None else min(self.t0, t)  # replayed hits can be older
            self.t1 = max(t, self.t1 or t)
        if damage and party:
            self.last_active, self.last_damage_wall = t, time.time()
        a = self.actors[caster]
        prefix, role, _ = skill_role(key)
        if role == "combo":
            # a combo is two of the player's heroes at once: their combo hits arrive
            # together (same message batch), so pair the heroes seen within 1 s
            a.combo_recent = [(tt, pp) for tt, pp in a.combo_recent if abs(t - tt) < 1.0]
            for _, other in a.combo_recent:
                if other != prefix:
                    a.combo_partner[prefix], a.combo_partner[other] = other, prefix
            a.combo_recent.append((t, prefix))
        if caster in self.me:
            self.link_cast(t, key, [h for h in dealt if not h["heal"]])
        for h in dealt:
            if h["heal"]:
                a.heal += h["damage"]
                continue
            a.add(key, h)
            a.heroes[hero].add(key, h)
            ta = a.targets.get(h["target"])
            if ta is None:
                ta = a.targets[h["target"]] = Actor()
            ta.add(key, h)
            ta.heroes[hero].add(key, h)
            a.bins[int(t)] += h["damage"]
            ta.bins[int(t)] += h["damage"]
            if h["target"] in self.boss_profile and (name or caster in self.players or caster in self.me):
                self.boss_damage += h["damage"]           # what the guild ranking scores
            self.actors[h["target"]].taken += h["damage"]
            if (caster in self.players or caster in self.me) and \
                    h["target"] not in self.players and h["target"] not in self.me:
                self.track_enemy(t, h)
                if h["hp_after"] <= 0:
                    self.msg_kills.append((h["target"], a, hero, key, h["damage"]))

    def link_cast(self, t, key, hits):
        """Your hits onto the cast they came from, for the rotation: by the cast id
        (direct hits, 10040), else (skill objects: ultimate bombs, Daisy's lasers)
        the latest cast of the same skill within 15 s."""
        for h in hits:
            c = self.cast_ids.get(h.get("guid"))
            if c is None or c["key"] != key:
                c = next((c for c in reversed(self.rotation) if c["key"] == key), None)
                if c is None or t - c["t"] > 15:
                    continue
            c["damage"] += h["damage"]
            c["hits"] += 1
            c["crits"] += h["crit"]
            self.rotation_ver += 1

    def track_enemy(self, t, h):
        """A player hit an enemy. Its HP comes from, best first: P2C_ReportProperty
        (exact HP), the hit responses (HP left; within one message the hits are not in
        order, so the lowest one counts, see handle_impact). Max HP: the HP in its
        spawn message when the meter saw it appear (full HP, shields not included);
        otherwise HP left + damage of the first hit, dropped again as soon as a hit
        does not lower the HP (a shield took it)."""
        tg = h["target"]
        e = self.enemies.get(tg)
        new = e is None
        name, spawn_hp = self.spawns.get(tg, (None, 0))
        if new:
            e = self.enemies[tg] = dict(no=len(self.enemies) + 1, name=name, first=t, last=t,
                                        spawn_hp=spawn_hp, est=h["hp_after"] + h["damage"],
                                        peak=h["hp_after"], hp=h["hp_after"], shielded=False,
                                        changed=False, exact=False, hits=0, dead_at=None,
                                        over=0, kill=None, pending_over=None, boss=tg in self.boss_ids,
                                        hist=[(t, h["hp_after"] + h["damage"])])
        e["last"] = max(e["last"], t)
        e["hits"] += 1
        if tg in self.boss_profile and e.get("alive_hp"):
            # the hit that took a leveling boss to 1 HP: what it dealt past the HP left (the HP
            # property before it is exact) goes to the next life; later hits at 1 HP go nowhere.
            # Hits come in pairs, the ~10% one landing first (the HP properties' order), so of
            # the hits that arrive with the kill and could have dealt it, the smallest did
            batch = e["kill_batch"] = e["kill_batch"] if e.get("kill_batch", (None,))[0] == t else (t, [])
            batch[1].append(h["damage"])
            if h["hp_after"] <= 1 and e.get("carry") is None and e.get("kill_t") is None:
                e["kill_t"] = t
            if e.get("kill_t") == t:
                fits = [d - e["alive_hp"] for d in batch[1] if d >= e["alive_hp"]]
                if fits:
                    e["carry"] = min(fits)
        hp, dmg = self.msg_hp.get(tg, (None, 0))
        self.msg_hp[tg] = (h["hp_after"] if hp is None else min(hp, h["hp_after"]), dmg + h["damage"])
        if h["hp_after"] > 0:                    # lowest HP it still had in this message
            self.msg_alive[tg] = min(self.msg_alive.get(tg, h["hp_after"]), h["hp_after"])
        if new:
            e["hp_start"] = spawn_hp or h["hp_after"] + h["damage"]

    def settle_kills(self):
        """Overdamage: damage beyond the HP the enemy had left. The killing hit gets
        the server's exact figure when P2C_ReportProperty already sent it (its raw HP
        goes negative, e.g. -127,718), else its damage minus the lowest HP the enemy
        still had (in this message, or before it). Hits on an enemy that is already
        dead are overdamage in full."""
        for tg, a, hero, key, dmg in self.msg_kills:
            e = self.enemies.get(tg)
            if e is None:
                continue
            if e["kill"] is not None:            # already dead: all of it is overdamage
                over = dmg
            else:
                if e["pending_over"] is not None:
                    over = e["pending_over"]
                else:
                    # lowest HP it is known to have had: in this message, or the latest
                    # (exact, from P2C_ReportProperty) value from before it
                    known = e["hp"] if e["hits"] > 1 else e.get("hp_start", 0)
                    before = min(self.msg_alive.get(tg, known), known) if known else self.msg_alive.get(tg, 0)
                    over = max(0, dmg - before) if before else 0
                e["kill"] = (a, hero, key, min(over, dmg), tg)
            over = min(over, dmg)
            e["over"] += over
            self.add_over(a, tg, hero, key, over)

    def exact_overdamage(self, e, over):
        """The server's raw HP for a kill; corrects an estimate made before it arrived."""
        if e["kill"] is None:
            e["pending_over"] = over
            return
        a, hero, key, est, tg = e["kill"]
        if over != est:
            self.add_over(a, tg, hero, key, over - est)
            e["over"] += over - est
            e["kill"] = (a, hero, key, over, tg)

    @staticmethod
    def add_over(a, tg, hero, key, over):
        for st in (a, a.targets.get(tg)):
            if st is not None:
                st.skill_over[key] += over
                st.heroes[hero].skill_over[key] += over

    def set_enemy_hp(self, e, hp, t, damage=0, authoritative=False):
        hp = max(0, hp)
        if authoritative:
            e["exact"] = True
        elif damage > 0 and hp == e["hp"] and hp > 0 and e["hits"] > 1:
            e["shielded"] = True                 # damage that did not lower the HP
        if e["hits"] > 1 and e["hp"] <= max(1, 0.005 * e["peak"]) and hp > max(1000, 10 * e["hp"]):
            e["resets"] = e.get("resets", 0) + 1     # "killed" at 1 HP, back with full (higher) HP: a level up
            # the killing hit's overkill carries into the new life: refilled short of its full HP by it
            e["life_hp"] = hp + e["carry"] if e.get("carry") is not None else None
            e["carry"] = e["kill_t"] = None
        if hp > 1:
            e["alive_hp"] = hp                       # HP before a killing hit (see track_enemy)
        if hp != e["hp"]:
            e["changed"] = True
            if len(e["hist"]) < 20000:           # HP over time, for the graph
                e["hist"].append((t, hp))
        e["hp"] = hp
        e["peak"] = max(e["peak"], hp)
        if hp <= 0:
            e["dead_at"] = e["dead_at"] or t
            if e["boss"] and self.boss_mode and self.frozen is None and \
                    all(x["dead_at"] is not None for x in self.enemies.values() if x["boss"]):
                self.frozen = e["dead_at"]       # boss mode: the fight ends with the last boss
                self.log(t, f"boss {e['name']} defeated: fight ends")
        else:                                    # alive (again): a later kill is a new one
            e["dead_at"], e["kill"], e["pending_over"] = None, None, None
            if e["boss"] and self.frozen is not None:
                self.frozen = None               # it came back (a next phase): the fight goes on

    @staticmethod
    def enemy_max(e):
        if e["spawn_hp"]:
            return max(e["spawn_hp"], e["peak"])
        return e["peak"] if e["shielded"] else max(e["peak"], e["est"])

    def enemy_bars(self, limit=5):
        """Every enemy hit since the last reset, in the order they were first hit
        (dead ones too); with more than `limit`, the most recently hit ones. Dicts with
        aid, label, hp, max, frozen (the server does not report its HP), dead, over."""
        with self.lock:
            shown = sorted(self.enemies.items(), key=lambda kv: -kv[1]["last"])[:max(1, limit)]
            shown.sort(key=lambda kv: kv[1]["first"])
            return [dict(aid=aid, label=e["name"] or f"Enemy {e['no']}", hp=e["hp"], max=max(1, self.enemy_max(e)),
                         frozen=e["hits"] >= 3 and not (e["changed"] or e["exact"] or e["spawn_hp"]),
                         dead=e["dead_at"] is not None, over=e["over"], resets=e.get("resets", 0),
                         level=self.boss_level(aid, e))
                    for aid, e in shown]

    def boss_level(self, aid, e):
        """(level, max level) of a boss that levels up when killed (BOSS_PROFILES), when the
        meter saw it spawn (at level 1); else None."""
        prof = BOSS_PROFILES.get(self.boss_profile.get(aid))
        if not prof or not e.get("spawn_hp"):
            return None
        return min(prof["levels"], 1 + e.get("resets", 0)), prof["levels"]

    def boss_skill(self, t, caster, skill, hits, buff=None):
        """A boss's own skill (a hit, or a marker it puts on itself): learns which boss
        has a BOSS_PROFILES entry from its skill names, and follows its ultimate: the
        start marker starts the charge, the hit (or its marker) ends it."""
        key = self.boss_profile.get(caster)
        if key is None:                          # its spawn was missed: known by its skills, but only
            key = next((k for k, pr in BOSS_PROFILES.items() if skill.startswith(pr["prefix"])), None)
            if key is None or key in self.boss_profile.values() or caster in self.players or \
                    caster in self.me or not (skill == BOSS_PROFILES[key]["ult_start"] or caster in self.enemies):
                return                           # (its summons and objects use the same skill names)
            self.boss_profile[caster] = key
            self.boss_ids.add(caster)
            if caster in self.enemies:
                self.enemies[caster]["boss"] = True
        prof = BOSS_PROFILES[key]
        u = self.ults.setdefault(caster, dict(start=None, hits=[]))
        if skill == prof["ult_start"]:
            if u["start"] is None or t - u["start"] > 5:
                u["start"] = t
                self.log(t, f"boss {caster} starts charging its ultimate")
        elif skill == prof["ult_hit"]:
            dmg = [(h["target"], h["damage"]) for h in hits if not h["no_damage"] and not h["heal"]]
            last = u["hits"][-1] if u["hits"] else None
            if last is not None and t - last["t"] < 3:   # the same ultimate: more of its hits
                last["dmg"] += dmg
                return
            if u["start"] is not None and 10 < t - u["start"] < 120:
                self.ult_charge[key] = t - u["start"]   # its real charge time, for the next one
            u["hits"].append(dict(t=t, start=u["start"], dmg=dmg))
            u["start"] = None
            self.log(t, f"boss {caster} ultimate lands")

    def ult_status(self):
        """Each boss with a known ultimate in this fight: name, level, charging (s left of
        the charge time) or not, how often it landed and its last one (when, total
        damage, the player hit hardest)."""
        with self.lock:
            now, out = self.now(), []
            for boss, key in self.boss_profile.items():
                e = self.enemies.get(boss)
                if e is None:
                    continue
                u = self.ults.get(boss, {})
                charge = self.ult_charge.get(key, BOSS_PROFILES[key]["charge"])
                left = u["start"] + charge - now if u.get("start") is not None else None
                if left is not None and left < -5:   # it never landed (interrupted?): not charging
                    left = None
                last = u["hits"][-1] if u.get("hits") else None
                info = None
                if last:
                    worst = max(last["dmg"], key=lambda x: x[1]) if last["dmg"] else None
                    info = dict(t=last["t"] - (self.t0 if self.t0 is not None else last["t"]),
                                dmg=sum(d for _, d in last["dmg"]),
                                worst=(self.who(worst[0]), worst[1]) if worst else None)
                out.append(dict(boss=boss, name=self.enemy_label(boss), charging=left is not None,
                                left=max(0.0, left or 0.0), total=charge, last=info, count=len(u.get("hits", [])),
                                level=self.boss_level(boss, e), resets=e.get("resets", 0)))
            return out


    def enemy_label(self, aid):
        e = self.enemies.get(aid)
        return (e["name"] or tr("Enemy {n}", n=e["no"])) if e else None

    def set_roster(self, t, found):
        """The dungeon's players (10140). They are players for sure: one that was taken
        for another player's skill object before the list came is split off again
        (from then on; what it dealt until then stays with the other player). Each list
        holds the whole party, you too: one sharing no actor id with the players known
        so far is a new room."""
        known = set(self.roster) or self.players | self.me
        if known and not known & found.keys():
            self.new_room(t, f"a player list of {len(found)} new actor ids")
        for aid, name in found.items():
            if self.roster.get(aid) != name:
                self.log(t, f"player {aid} is {name}")
            if aid in self.owner:
                self.log(t, f"actor {aid} is a player, not a skill object of {self.owner.pop(aid)}")
            self.main_actors.add(aid)
        self.roster.update(found)
        self.roster_t = t
        if self.me_actor is None:
            self.identify_me(t)                         # a stat sheet that came before the list

    def resolve_owner(self, t, caster, skill):
        """Some skill parts (e.g. the ultimate's '..._skill_q_bomb') and summons are dealt
        by a spawned object with its own actor id: credited to the player it belongs to,
        instead of showing a second row. Exact when the server says so (the dungeon's
        player list, a summon's spawn message); otherwise guessed: the actor that uses
        that hero + weapon's skills directly."""
        if caster in self.roster:
            return caster
        owner = self.spawn_owner.get(caster)
        if owner is not None:
            if self.owner.get(caster) != owner:
                self.owner[caster] = owner
                self.log(t, f"actor {caster} ({skill}) is a summon of {owner}")
            return owner
        prefix, slot, part = split_skill(skill)
        if not prefix or prefix[:1].isdigit():
            return self.owner.get(caster, caster)
        if slot == "skill_r":
            ULT_IS_R.add(prefix)
        if caster in self.owner:
            if part and slot not in BASE_PARTS:
                return self.owner[caster]
            # a guessed skill object that casts a skill of its own: a player after all
            # (several players on the same hero), counted on its own from now on
            self.log(t, f"actor {caster} ({skill}) is a player, not a skill object of {self.owner.pop(caster)}")
        if not part or slot in BASE_PARTS:
            self.main_actors.add(caster)
            self.prefix_actor[prefix] = caster
        elif caster not in self.main_actors:
            owner = self.prefix_actor.get(prefix)
            if owner is not None and owner != caster:
                self.owner[caster] = owner
                self.log(t, f"actor {caster} ({skill}) is a skill object of {owner}")
                return owner
        return caster

    # ---- output
    def label(self, aid):
        """'Me', the player's character name (show_names, when the dungeon's player list
        gave it) or 'Player 2', 'Player 3', ... (numbered in the order they first dealt
        damage, so a number stays with the player when the ranking changes; only the
        players in this fight count), or 'Mob ...'."""
        if aid in self.me:
            return tr("Me")
        if aid in self.players and Meter.show_names and self.roster.get(aid):
            return self.roster[aid]
        if aid in self.players:
            others = [p for p in self.player_order if p not in self.me and (p in self.actors or p == aid)]
            return tr("Player {n}", n=others.index(aid) + 2)
        return f"Mob {aid & 0xFFFFFF:06x}"

    def duration(self, target=None):
        e = self.enemies.get(target) if target is not None else None
        if e is not None:
            return max(1.0, e["last"] - e["first"])
        end = self.frozen if self.frozen is not None else self.t1
        return max(1.0, (end - self.t0)) if self.t0 is not None else 0.0

    def snapshot(self, mode="done", show_all=False, target=None):
        """(duration, player rows), ranked. A row is a dict: label, value, parent
        (the value the % is taken of), sub, me, aid. Monsters are only listed for
        damage taken, with show_all. With target (an enemy id), damage done counts
        only the damage dealt to that enemy, over the time it was being hit."""
        with self.lock:
            target = target if mode == "done" else None
            dur = self.duration(target)
            players = []
            for aid, a in self.actors.items():
                if target is not None:
                    a = a.targets.get(target)
                    if a is None:
                        continue
                v = a.done if mode == "done" else a.taken
                if v <= 0:
                    continue
                is_player = aid in self.players or aid in self.me
                if not is_player and (mode == "done" or not show_all):
                    continue
                sub = a.sub(dur) if mode == "done" else f"{v / max(dur, 1):,.0f}/s"
                players.append((v, aid, sub))
            players.sort(key=lambda p: -p[0])
            total = sum(p[0] for p in players)
            return dur, [dict(level=0, label=self.label(aid), value=v, parent=total, sub=sub,
                              me=aid in self.me, aid=aid) for v, aid, sub in players]

    def details(self, aid, view=None, target=None):
        """(label, rows, summary) for one player's detail panel: hero rows (level 1)
        and skill rows (level 2, or 1 without hero rows), damage done (to target
        only); summary is a dict of done, dps, crit and max_hit."""
        view = view or DEFAULT_VIEW
        with self.lock:
            dur = self.duration(target)
            a = self.actors.get(aid)
            src = a.targets.get(target) if (a is not None and target is not None) else a
            me = aid in self.me
            rows = detail_rows(src, view["me" if me else "others"], dur, a.combo_partner) if src else []
            for r in rows:
                r.update(me=me, aid=aid)
            summary = dict(done=src.done if src else 0, dps=(src.done if src else 0) / max(dur, 1),
                           crit=100 * src.crits / max(1, src.hits) if src else 0,
                           max_hit=src.max_hit if src else 0)
            return self.label(aid), rows, summary

    def rotation_groups(self):
        """Your skill rotation (preview): your cast requests in order, see rotation_groups."""
        with self.lock:
            casts = [dict(c) for c in self.rotation]
            start = min(casts[0]["t"], self.t0) if casts and self.t0 is not None else None
            damage = sum(self.actors[a].done for a in self.me if a in self.actors)
        return rotation_groups(casts, start), damage

    def add_buffs(self, t, caster, target, items):
        """Buffs and debuffs put on target (10049, a full list each time): one entry per
        buff instance, its end moved when the server refreshes it. Permanent ones (end 0:
        passives, gear auras) are left out. The game's internal ones (no in-game name in
        buff_names.json) are kept, but only shown with 'hidden effects' on."""
        for inst, tid, start, end, stacks, skill in items:
            if skill and self.owner.get(caster, caster) == target:
                self.boss_skill(t, target, skill, (), buff=inst)
            if start <= 0 or end <= start:
                continue
            off = t - start / 1000                   # never less than the network delay
            self.buff_offset = off if self.buff_offset is None else min(self.buff_offset, off)
            b = self.buffs.get(inst)
            if b is None:
                self.buffs[inst] = dict(caster=self.owner.get(caster, caster), target=target, tid=tid,
                                        skill=skill, start=start / 1000, end=end / 1000)
            elif b["end"] != end / 1000:
                if end / 1000 > b["end"]:           # re-applied: it runs again from now
                    b.setdefault("refreshes", []).append(t - self.buff_offset)
                b["end"] = end / 1000
            else:
                continue
            self.buff_ver += 1

    def now(self):
        """The current time on the capture's clock (a loaded fight: its end)."""
        if self.loaded:
            win = self.fight_window()
            return win[1] if win else 0.0
        return self.last_t + (time.time() - self.last_packet) if self.last_t else time.time()

    def fight_window(self, target=None):
        e = self.enemies.get(target) if target is not None else None
        if e is not None:
            return e["first"], e["dead_at"] or e["last"]
        if self.t0 is None:
            return None
        return self.t0, self.frozen if self.frozen is not None else self.t1

    # ---- effects (buffs and debuffs): what they are, on whom, by whom
    def effect_info(self, b):
        """(key, label, icon, named) of a buff instance. key: buff_key (its in-game English
        name and icon: every level / re-application of it is one effect), '#<buff id>' for
        internal ones."""
        tid, skill = b["tid"], b["skill"]
        icon = (_icon("buff_" + BUFF_ICONS[tid]) if tid in BUFF_ICONS else None) or \
            (skill_icon(skill_key(skill)) if skill else None)       # the game's buff icon, else the skill's
        if tid in BUFF_EN:
            return buff_key(tid), buff_name(tid), icon, True
        what = skill_label(skill_key(skill)) if skill else tr("Buff #{n}", n=tid)
        return f"#{tid}", f"{what} ({tr('hidden')})", icon, False

    def who(self, aid, hero=None):
        """Label of an effect's caster or target: Me / Player 2 (· hero, when given) or
        the enemy's name."""
        if aid in self.me or aid in self.players:
            return self.label(aid) + (f" · {hero}" if hero else "")
        return self.enemy_label(aid) or (self.spawns.get(aid, (None,))[0]) or tr("Enemy")

    def effect_rows(self, show_hidden=False):
        """Every effect instance involving the party or an enemy it fought, with local
        times: dicts with key, label, icon, named, caster, target, start, end, tid."""
        off = self.buff_offset
        if off is None:
            return []
        party = self.players | self.me
        rows = []
        for b in self.buffs.values():
            caster = self.owner.get(b["caster"], b["caster"])
            tg = b["target"]
            if not (tg in party or tg in self.enemies or caster in party):
                continue
            key, label, icon, named = self.effect_info(b)
            if not named and not show_hidden:
                continue
            refreshes = [x + off for x in b.get("refreshes", ())]
            rows.append(dict(key=key, label=label, icon=icon, named=named, caster=caster, target=tg,
                             start=b["start"] + off, end=b["end"] + off, tid=b["tid"], refreshes=refreshes,
                             since=refreshes[-1] if refreshes else b["start"] + off,    # its last (re)application
                             hero=hero_name(b["skill"]) if b["skill"] else None))
        return rows

    def effects_live(self, show_hidden=False):
        """Live effects tracker: what is on whom right now. [(target, label, is_party,
        rows)], you first, then teammates, then enemies; rows (one per effect, the
        longest-lasting instance) with caster label, left and total (s)."""
        with self.lock:
            now = self.now()
            party = self.players | self.me
            best = {}
            for r in self.effect_rows(show_hidden):
                if r["start"] <= now < r["end"]:
                    k = (r["target"], r["key"])
                    if k not in best or r["end"] > best[k]["end"]:
                        best[k] = r
            out = collections.defaultdict(list)
            for (tg, _), r in best.items():
                out[tg].append(dict(r, who=self.who(r["caster"], r["hero"]), left=r["end"] - now,
                                    total=r["end"] - r["since"]))
            order = sorted(out, key=lambda tg: (tg not in self.me, tg not in party, self.who(tg)))
            return [(tg, self.who(tg, self.current_hero.get(tg)), tg in party,   # affects the hero out now
                     sorted(out[tg], key=lambda r: r["left"])) for tg in order]

    def effects_log(self, show_hidden=False):
        """Effect application tracker: every application, by caster -> target, in the order
        they happened. [(caster label, target label, rows)] (groups by their first
        application); rows with t (s into the fight), dur (s), active, and refreshed (the
        same effect was still on that target from before: re-applied, which also shows as
        a new row when the server keeps the same instance and only moves its end)."""
        with self.lock:
            now = self.now()
            rows = sorted(self.effect_rows(show_hidden), key=lambda r: r["start"])
            t0 = self.t0 if self.t0 is not None else (rows[0]["start"] if rows else 0)
            last_end, groups = {}, {}
            for r in rows:
                k = (r["target"], r["key"])
                refreshed = last_end.get(k, -1e18) > r["start"]
                last_end[k] = max(last_end.get(k, -1e18), r["end"])
                g = groups.setdefault((r["caster"], r["hero"], r["target"]), [])
                starts = [r["start"]] + r["refreshes"]        # re-applications of the same instance
                for i, a in enumerate(starts):
                    b = starts[i + 1] if i + 1 < len(starts) else r["end"]
                    g.append(dict(r, t=a - t0, dur=b - a, refreshed=refreshed or i > 0,
                                  active=a <= now < b))
            for g in groups.values():
                g.sort(key=lambda x: x["t"])
            return [(self.who(c, hero), self.who(tg), g) for (c, hero, tg), g in groups.items()]

    def effects_watch(self, keys):
        """Specific effect tracker: the watched effects (by key) active now, the
        longest-lasting one per effect and target: dicts with key, label, icon, left,
        total, target (label), mine (on you)."""
        if not keys:
            return []
        with self.lock:
            now = self.now()
            best = {}
            for r in self.effect_rows(show_hidden=True):
                if r["key"] in keys and r["start"] <= now < r["end"]:
                    k = (r["target"], r["key"])
                    if k not in best or r["end"] > best[k]["end"]:
                        best[k] = r
            return sorted((dict(r, left=r["end"] - now, total=r["end"] - r["since"], who=self.who(r["target"]),
                                mine=r["target"] in self.me) for r in best.values()), key=lambda r: r["left"])

    def buff_uptime(self, aid, target=None, show_hidden=False):
        """Uptime for one player over the fight (or the time target was being hit): dict
        of sections -> rows. 'on': effects on the player from the party, 'applied': ones
        the player put on enemies (on target only, with target), 'enemy': ones enemies put
        on the player. One row per effect (effect_info key), so a re-application, also
        before the last one ended, is the same row and overlaps count once: key, label,
        icon, uptime (0..1), n (applications), total and avg (s)."""
        with self.lock:
            win = self.fight_window(target)
            party = self.players | self.me
            if win is None:
                return {}
            w0, w1 = win
            span = max(1.0, w1 - w0)
            groups = collections.defaultdict(lambda: collections.defaultdict(list))
            info = {}
            for r in self.effect_rows(show_hidden):
                if r["target"] == aid:
                    sec = "on" if r["caster"] in party else "enemy"
                elif r["caster"] == aid and r["target"] not in party and (target is None or r["target"] == target):
                    sec = "applied"
                else:
                    continue
                s0, s1 = max(w0, r["start"]), min(w1, r["end"])
                if s1 > s0:
                    groups[sec][r["key"]].append((s0, s1))
                    info.setdefault(r["key"], r)
        out = {}
        for sec, keys in groups.items():
            rows = []
            for key, iv in keys.items():
                iv.sort()
                total, cur0, cur1 = 0.0, None, None
                for s0, s1 in iv:                     # union: re-applications count once
                    if cur1 is None or s0 > cur1:
                        total += (cur1 - cur0) if cur1 is not None else 0
                        cur0, cur1 = s0, s1
                    else:
                        cur1 = max(cur1, s1)
                total += cur1 - cur0
                rows.append(dict(key=key, label=info[key]["label"], icon=info[key]["icon"],
                                 uptime=min(1.0, total / span), n=len(iv), total=total,
                                 avg=sum(b - a for a, b in iv) / len(iv)))
            rows.sort(key=lambda r: -r["uptime"])
            out[sec] = rows
        return out

    def graph(self, target=None):
        """Damage over time: (start, end, [(aid, label, me, {second: damage})], hp) with
        hp the HP history [(t, fraction)] of target, else of the fight's boss."""
        with self.lock:
            win = self.fight_window(target)
            if win is None:
                return None
            series = []
            for aid, a in self.actors.items():
                if aid not in self.players and aid not in self.me:
                    continue
                src = a.targets.get(target) if target is not None else a
                if src is not None and src.bins:
                    series.append((aid, self.label(aid), aid in self.me, dict(src.bins)))
            e = self.enemies.get(target) if target is not None else \
                next((x for x in self.enemies.values() if x["boss"]), None)
            hp = []
            if e is not None:                        # a boss that resets (levels up): each life its own bar
                top, prev = e.get("spawn_hp") or 0, None
                for t, v in e["hist"]:
                    if prev is not None and prev <= max(1, 0.005 * top) and v > max(1000, 10 * prev):
                        top = 0
                    top = max(top, v)
                    hp.append((t, min(1.0, v / max(1, top))))
                    prev = v
            return win[0], win[1], series, hp

    def boss_summary(self):
        """The fight's boss, for the summary row: name, time (to the kill), team
        damage and DPS, killed. None without a boss."""
        with self.lock:
            bosses = [e for e in self.enemies.values() if e["boss"]]
            if not bosses or self.t0 is None:
                return None
            dur = self.duration()
            team = sum(a.done for aid, a in self.actors.items() if aid in self.players or aid in self.me)
            levels = [self.boss_level(aid, e) for aid, e in self.enemies.items() if e["boss"]]
            return dict(name=" + ".join(e["name"] or tr("Enemy {n}", n=e["no"]) for e in bosses), dur=dur,
                        team=team, dps=team / max(1.0, dur), killed=self.frozen is not None,
                        level=next((lv for lv in levels if lv), None),
                        resets=sum(e.get("resets", 0) for e in bosses))

    def learn_level_score(self, level, score):
        """The server's score on reaching a level: the same in every run, so it is kept
        (BOSS_SCORES_FILE) to tell the next runs what each life is worth."""
        key = next(iter(self.boss_profile.values()), None)
        if key is None or level < 2 or self.level_scores[key].get(level) == score:
            return
        self.level_scores[key][level] = score
        learned = {k: {lv: s for lv, s in v.items() if BOSS_PROFILES[k].get("scores", {}).get(lv) != s}
                   for k, v in self.level_scores.items()}
        try:
            with open(BOSS_SCORES_FILE, "w", encoding="utf-8") as f:
                json.dump({k: v for k, v in learned.items() if v}, f, indent=1)
        except OSError:
            pass

    def score_boss(self):
        """(actor, BOSS_PROFILES key) of the ranking boss in this fight hit last, or None."""
        bosses = [(a, k) for a, k in self.boss_profile.items() if a in self.enemies]
        return max(bosses, key=lambda b: self.enemies[b[0]]["last"]) if bosses else None

    def boss_score(self):
        """A boss that scores for a ranking (BOSS_PROFILES score), in this fight: est (the
        live score), server and level (its last exact one, sent at each level-up), final
        (the run's result). None without such a boss. est: the server's last score plus
        this life's HP removed, its full HP from its refill plus the overkill carried into
        it (life_hp), else from the next level's score (level_scores: the difference over
        the points per damage), else plus the party's damage since it."""
        with self.lock:
            sb = self.score_boss()
            if sb is None or self.t0 is None:
                return None
            aid, key = sb
            ratio = BOSS_PROFILES[key].get("score")
            if not ratio:
                return None
            e, cp = self.enemies[aid], self.score_cp
            if cp is None and self.boss_level(aid, e) == (1, BOSS_PROFILES[key]["levels"]):
                cp = dict(level=1, score=0, damage=0, resets=-1)   # seen spawn, no level-up yet: its first life
            nxt = self.level_scores[key].get(cp["level"] + 1) if cp else None
            life_hp = (e.get("life_hp") if e.get("resets") else e.get("spawn_hp")) or None
            if cp and cp.get("resets") is not None and life_hp and e.get("resets", 0) > cp["resets"]:
                # this life's full HP: its refill plus the overkill carried into it (the first
                # life: its spawn HP); at 1 HP it is killed, the server's score for it to come
                est = cp["score"] + max(0.0, life_hp - (0 if e["hp"] <= 1 else e["hp"])) * ratio
            elif cp and cp.get("resets") is not None and e["hp"] <= 1:
                est = cp["score"]                       # scored, not refilled yet
            elif nxt is not None and nxt > cp["score"] and cp.get("resets") is not None:
                # by HP, not damage: the killing hit's overkill carries into the next life (its
                # refill is short of the full HP by it) and hits at 1 HP score nothing. At 1 HP:
                # killed, and the server's score for it not here yet when no refill came since it
                life = nxt - cp["score"]
                if e["hp"] <= 1:
                    est = nxt if e.get("resets", 0) > cp["resets"] else cp["score"]
                else:
                    est = cp["score"] + min(life, max(0.0, life - e["hp"] * ratio))
            elif cp:
                est = cp["score"] + (self.boss_damage - cp["damage"]) * ratio
            else:
                est = self.boss_damage * ratio
            cp = self.score_cp
            return dict(est=est, server=cp["score"] if cp else None, level=cp["level"] if cp else None,
                        final=self.score_final, ratio=ratio)

    def fight_summary(self):
        """The live fight as a history row (the keys of a saved file's summary), or None
        before the party dealt damage."""
        with self.lock:
            if self.t0 is None or self.loaded:
                return None
            team = sum(a.done for aid, a in self.actors.items() if aid in self.players or aid in self.me)
            if team <= 0:
                return None
            return dict(name=self.fight_name(), saved=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.t0)),
                        duration=self.duration(), team=team, killed=self.frozen is not None,
                        me_damage=sum(self.actors[a].done for a in self.me if a in self.actors),
                        boss=any(e["boss"] for e in self.enemies.values()))

    def fight_name(self):
        bosses = [e for e in self.enemies.values() if e["boss"]]
        if bosses:
            return " + ".join(e["name"] or tr("Enemy {n}", n=e["no"]) for e in bosses)
        named = sorted((e for e in self.enemies.values() if e["name"]), key=lambda e: -e["hits"])
        return named[0]["name"] if named else tr("Fight")

    def export_fight(self):
        """The fight as a JSON-able dict (history files, Export); load_fight reads it."""
        enemies = {str(aid): {k: v for k, v in e.items() if k not in ("kill", "pending_over")}
                   for aid, e in self.enemies.items()}
        team = sum(a.done for aid, a in self.actors.items() if aid in self.players or aid in self.me)
        return dict(format=FIGHT_FORMAT, version=1, saved=time.strftime("%Y-%m-%d %H:%M:%S"),
                    name=self.fight_name(), t0=self.t0, t1=self.t1, frozen=self.frozen,
                    duration=self.duration(), team=team, killed=self.frozen is not None,
                    boss=any(e["boss"] for e in self.enemies.values()),
                    me_damage=sum(self.actors[a].done for a in self.me if a in self.actors),
                    me=list(self.me), me_actor=self.me_actor, players=list(self.players),
                    player_order=self.player_order, names={str(k): v for k, v in self.names.items()},
                    owner={str(k): v for k, v in self.owner.items()},
                    player_names={str(k): v for k, v in self.roster.items() if k in self.players or k in self.me},
                    actors={str(k): actor_dict(a) for k, a in self.actors.items()}, enemies=enemies,
                    rotation=list(self.rotation), buffs={str(k): b for k, b in self.buffs.items()},
                    buff_offset=self.buff_offset,
                    boss_profile={str(k): v for k, v in self.boss_profile.items()},
                    ults={str(k): v for k, v in self.ults.items()}, boss_damage=self.boss_damage,
                    score_cp=self.score_cp, score_final=self.score_final)

    @classmethod
    def load_fight(cls, d):
        """A Meter holding a saved fight, for the overlay to show (no capture, no log)."""
        if not isinstance(d, dict) or d.get("format") != FIGHT_FORMAT:
            raise ValueError("not an SDS Meter fight file")
        m = cls(log=False)
        m.t0, m.t1, m.frozen = d["t0"], d["t1"], d.get("frozen")
        m.me, m.me_actor = set(d.get("me", [])), d.get("me_actor")
        m.players, m.player_order = set(d.get("players", [])), list(d.get("player_order", []))
        m.names = {int(k): v for k, v in d.get("names", {}).items()}
        m.owner = {int(k): v for k, v in d.get("owner", {}).items()}
        m.roster = {int(k): v for k, v in d.get("player_names", {}).items()}
        m.actors = collections.defaultdict(Actor, {int(k): actor_load(v) for k, v in d.get("actors", {}).items()})
        for k, e in d.get("enemies", {}).items():
            e = dict(e, kill=None, pending_over=None, hist=[tuple(x) for x in e.get("hist", [])])
            e.setdefault("boss", False)
            m.enemies[int(k)] = e
        m.rotation = collections.deque(d.get("rotation", []), maxlen=ROTATION_MAX)
        m.cast_ids = {c["guid"]: c for c in m.rotation}
        m.buffs = {int(k): b for k, b in d.get("buffs", {}).items()}
        m.buff_offset = d.get("buff_offset")
        m.boss_profile = {int(k): v for k, v in d.get("boss_profile", {}).items() if v in BOSS_PROFILES}
        m.ults = {int(k): dict(start=None, hits=v.get("hits", [])) for k, v in d.get("ults", {}).items()}
        m.boss_damage, m.score_cp, m.score_final = d.get("boss_damage", 0), d.get("score_cp"), d.get("score_final")
        m.loaded = d
        return m

    def finish_fight(self):
        """Save the fight to the history folder (on a reset, boss kill, idle clear or
        close) when the party dealt damage in it, so it stays in the history."""
        if not self.history_dir or self.t0 is None or self.loaded:
            return None
        team = sum(a.done for aid, a in self.actors.items() if aid in self.players or aid in self.me)
        if team <= 0:
            return None
        try:
            os.makedirs(self.history_dir, exist_ok=True)
            name = re.sub(r"[^\w\- ]+", "", self.fight_name()).strip()[:40] or "Fight"
            path = os.path.join(self.history_dir,
                                time.strftime("%Y%m%d-%H%M%S", time.localtime(self.t0)) + f"_{name}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.export_fight(), f, ensure_ascii=False, separators=(",", ":"))
            self.saved = path
            old = sorted(x for x in os.listdir(self.history_dir) if re.match(r"\d{8}-\d{6}_.*\.json$", x))
            for x in old[:-HISTORY_MAX]:             # only our own fight files
                os.remove(os.path.join(self.history_dir, x))
            return path
        except (OSError, TypeError, ValueError) as e:
            self.log(time.time(), f"could not save the fight: {e}")
            return None

    def status(self):
        with self.lock:
            s = self.key.status()
            if not self.packets:
                return s + " · waiting for game traffic (ports %d-%d)" % self.ports
            if not self.s2c_packets and time.time() - self.first_packet > 10:
                return s + " · only outgoing traffic seen: pick the adapter in Cfg > Network adapter"
            return s + (" · no traffic" if time.time() - self.last_packet > 10 else " · live")


def pcap_thread(args, meter, errq):
    ports = port_range(args)
    try:
        npcap.read_file(args.pcap, ports, lambda *seg: meter.feed(*seg, ports))
    except OSError as e:
        errq.put(f"cannot read {args.pcap}: {e}")
    meter.capture_done = True


# -------------------------------------------------------------------- GUI ---

def fmt_short(n):
    for div, suf in ((1e9, "B"), (1e6, "M"), (1e3, "K")):
        if n >= div:
            return f"{n / div:.2f}{suf}"
    return str(int(n))


POS_FILE = os.path.join(USER, "meter_pos.json")
DETAIL_POS_FILE = os.path.join(USER, "meter_detail_pos.json")
WATCH_POS_FILE = os.path.join(USER, "meter_watch_pos.json")     # the watch bar
SCORE_POS_FILE = os.path.join(USER, "meter_score_pos.json")     # the guild boss score window
CONFIG_FILE = os.path.join(USER, "meter_config.json")
HISTORY_DIR = os.path.join(USER, "history")                     # finished fights (Meter.finish_fight)
HOTKEY_LOCK = 1                                 # Ctrl+Shift+M, lock / unlock: the meter's only key


def load_view():
    import copy, json
    view = copy.deepcopy(DEFAULT_VIEW)
    try:
        saved = json.load(open(CONFIG_FILE))
        for who in (("me", "others") if saved.get("version", 0) >= 2 else ()):
            for k in ("heroes", "skills"):
                view[who][k] = bool(saved.get(who, {}).get(k, view[who][k]))
        for k in ("max_rows",):
            view[k] = max(1, int(saved.get(k, view[k])))
        for k in ("icon_size", "font_size"):
            if saved.get(k) in SIZE_NAMES:
                view[k] = saved[k]
        view["show_all"] = bool(saved.get("show_all", False))
        view["exact"] = bool(saved.get("exact", False))
        view["bar_details"] = bool(saved.get("bar_details", True))
        view["player_names"] = bool(saved.get("player_names", True))
        view["lang"] = saved.get("lang") if saved.get("lang") in LANGS else "en"
        view["start_locked"] = bool(saved.get("start_locked", False))
        view["tutorial_seen"] = bool(saved.get("tutorial_seen", False))
        view["enemy_hp"] = bool(saved.get("enemy_hp", True))
        view["max_enemies"] = max(1, min(20, int(saved.get("max_enemies", 5))))
        view["auto_reset"] = max(0, min(3600, int(saved.get("auto_reset", 60))))
        if saved.get("version", 0) < 3 and view["auto_reset"] == 0:
            view["auto_reset"] = 60              # the fight history keeps cleared fights: on by default
        view["opacity"] = max(20, min(100, int(saved.get("opacity", 88))))
        view["iface"] = str(saved.get("iface") or "all")
        view["rot_small"] = bool(saved.get("rot_small", False))
        view["boss_mode"] = bool(saved.get("boss_mode", True))
        view["watch"] = []
        for k in (k for k in saved.get("watch", []) if isinstance(k, str)):   # watched before keys had
            same = sorted({buff_key(t) for t, en in BUFF_EN.items() if en == k})   # the icon: all of that name
            view["watch"] += [x for x in (same or [k]) if x not in view["watch"]]
        view["watch"] = view["watch"][:50]
        view["fx_hidden"] = bool(saved.get("fx_hidden", False))
        view["sizes"] = {k: [int(v[0]), int(v[1])] for k, v in (saved.get("sizes") or {}).items()
                         if isinstance(v, list) and len(v) == 2}
        view["auto_detail"] = bool(saved.get("auto_detail", True))
        if saved.get("version", 0) < 4 and saved.get("detail_min", True):   # the size button was its own
            view["me"]["skills"] = view["others"]["skills"] = False         # setting: minimized = no skills
        for k in ("watch_bar", "gb_score"):
            view[k] = bool(saved.get(k, DEFAULT_VIEW[k]))
    except (OSError, ValueError, TypeError, AttributeError):
        view["show_all"] = False
    return view


def save_view(view):
    import json
    try:
        json.dump(dict(view, version=4), open(CONFIG_FILE, "w"), indent=2)
    except OSError:
        pass


def input_thread(events):
    """Ctrl+Shift+M, lock / unlock: the meter's only key. A Windows hotkey (RegisterHotKey),
    so it arrives while the game has focus too. Nothing is sent or injected, the game is
    untouched."""
    import ctypes
    from ctypes import wintypes
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    if not user32.RegisterHotKey(None, HOTKEY_LOCK, 0x2 | 0x4 | 0x4000, ord("M")):   # Ctrl+Shift, no repeat
        events.put(("err", tr("{k} is used by another program", k="Ctrl+Shift+M")))
        return
    msg = wintypes.MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        if msg.message == 0x0312 and msg.wParam == HOTKEY_LOCK:           # WM_HOTKEY
            events.put(("hotkey", HOTKEY_LOCK))


class OverlayWindow:
    """Win32 extended styles for the meter's own window: click-through when
    locked, never takes focus from the game, hidden from taskbar/alt-tab unless
    taskbar (the meter itself: the exe has no console window to show it is running)."""
    GWL_EXSTYLE, WS_EX_TRANSPARENT, WS_EX_LAYERED = -20, 0x20, 0x80000
    WS_EX_TOOLWINDOW, WS_EX_NOACTIVATE, WS_EX_APPWINDOW = 0x80, 0x08000000, 0x40000

    def __init__(self, root, taskbar=False):
        self.taskbar = taskbar
        self.win = root
        import ctypes
        self.u = ctypes.windll.user32
        self.u.GetWindowLongPtrW.restype = ctypes.c_ssize_t
        self.u.GetWindowLongPtrW.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.u.SetWindowLongPtrW.restype = ctypes.c_ssize_t
        self.u.SetWindowLongPtrW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_ssize_t]
        self.u.SetWindowPos.argtypes = [ctypes.c_void_p, ctypes.c_void_p] + [ctypes.c_int] * 4 + [ctypes.c_uint]
        self.u.GetAncestor.restype = ctypes.c_void_p
        self.u.GetAncestor.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        self.u.ShowWindow.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.u.SetLayeredWindowAttributes.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_ubyte, ctypes.c_uint32]
        self.u.BeginDeferWindowPos.restype = ctypes.c_void_p                  # raise_all: all windows at once
        self.u.BeginDeferWindowPos.argtypes = [ctypes.c_int]
        self.u.DeferWindowPos.restype = ctypes.c_void_p
        self.u.DeferWindowPos.argtypes = [ctypes.c_void_p] * 3 + [ctypes.c_int] * 4 + [ctypes.c_uint]
        self.u.EndDeferWindowPos.argtypes = [ctypes.c_void_p]
        self.WINEVENTPROC = ctypes.WINFUNCTYPE(None, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p,
                                               ctypes.c_long, ctypes.c_long, ctypes.c_uint, ctypes.c_uint)
        self.u.SetWinEventHook.restype = ctypes.c_void_p
        self.u.SetWinEventHook.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, self.WINEVENTPROC,
                                           ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
        root.update_idletasks()
        self.hwnd = self.u.GetAncestor(root.winfo_id(), 2)                   # GA_ROOT
        try:                                     # Windows 11: rounded corners (DWMWCP_ROUND)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(ctypes.c_void_p(self.hwnd), 33,
                                                       ctypes.byref(ctypes.c_int(2)), 4)
        except (OSError, AttributeError):
            pass

    def ex_style(self):
        return self.u.GetWindowLongPtrW(self.hwnd, self.GWL_EXSTYLE)

    def set_locked(self, locked):
        old = self.ex_style()
        ex = old | self.WS_EX_LAYERED | self.WS_EX_NOACTIVATE
        if self.taskbar:
            ex = (ex | self.WS_EX_APPWINDOW) & ~self.WS_EX_TOOLWINDOW
        else:
            ex |= self.WS_EX_TOOLWINDOW
        ex = ex | self.WS_EX_TRANSPARENT if locked else ex & ~self.WS_EX_TRANSPARENT
        self.u.SetWindowLongPtrW(self.hwnd, self.GWL_EXSTYLE, ex)
        # a layered window is only drawn once its alpha is set: Tk sets it below 100% opacity
        # only, so at 100% a window made layered here would stay invisible
        try:
            alpha = float(self.win.attributes("-alpha"))
        except (ValueError, TypeError):
            alpha = 1.0
        self.u.SetLayeredWindowAttributes(self.hwnd, 0, max(0, min(255, round(alpha * 255))), 0x2)   # LWA_ALPHA
        if (old ^ ex) & self.WS_EX_APPWINDOW:   # the taskbar only notices on hide + show
            self.u.ShowWindow(self.hwnd, 0)
            self.u.ShowWindow(self.hwnd, 4)
        self.keep_on_top(frame=True)

    def place(self, x, y, w, h):
        """Move and size the window, topmost, without activating it (Tk ignores the
        position of a -transparentcolor window)."""
        self.u.SetWindowPos(self.hwnd, -1, x, y, w, h, 0x10)              # HWND_TOPMOST, NOACTIVATE

    def move(self, x, y):
        self.u.SetWindowPos(self.hwnd, -1, x, y, 0, 0, 0x1 | 0x10)       # topmost, NOSIZE, NOACTIVATE

    def show(self, visible):
        self.u.ShowWindow(self.hwnd, 4 if visible else 0)        # SW_SHOWNOACTIVATE / SW_HIDE

    def keep_on_top(self, frame=False):
        # HWND_TOPMOST; NOSIZE|NOMOVE|NOACTIVATE -- never activates the overlay. FRAMECHANGED (frame)
        # only after a style change: it redraws the whole window, a flicker when done every few seconds
        self.u.SetWindowPos(self.hwnd, -1, 0, 0, 0, 0, 0x1 | 0x2 | 0x10 | (0x20 if frame else 0))


def run_gui(meter, errq, live=None):
    import json
    import tkinter as tk
    import tkinter.font as tkfont

    # palette: near-black panels, soft cards, blue bars for teammates, amber for you
    BG, PANEL, CARD, TOP, FAINT = "#101217", "#171a21", "#1d212a", "#0a0b0f", "#2b303b"
    FG, SUBFG, DIM = "#eef0f5", "#a9b0bd", "#6f7787"
    ACCENT, ACCENT_HI = "#f0a640", "#ffc46b"
    GOOD, WARN, BAD = "#4cc38a", "#f0b429", "#ef5350"
    BARS = {0: (("#25467a", "#5b9cff"), ("#6b4a1c", "#f0a640")),     # level: ((fill, edge) other, me)
            1: (("#1f3a63", "#4a83d6"), ("#5a3e18", "#d18d36")),
            2: (("#1a2f4f", "#3c6cb0"), ("#4a3314", "#b27630"))}
    MEDALS = {1: "#f2c94c", 2: "#c3cad6", 3: "#d08a52"}             # rank badge colours
    ENEMY_BG, ENEMY_FILL, ENEMY_EDGE, TARGET = "#2a1618", "#8f2a26", "#ff6a5c", "#ffc04d"
    MAX_PLAYERS, GAP, PAD, R = 10, 3, 6, 6                          # cards: gap, side margin, radius
    def on_screen(px, py):
        """True if (px, py) is on the virtual desktop (all monitors)."""
        try:
            import ctypes
            m = ctypes.windll.user32.GetSystemMetrics          # SM_X/YVIRTUALSCREEN, SM_CX/CYVIRTUALSCREEN
            vx, vy, vw, vh = m(76), m(77), m(78), m(79)
            return vx <= px < vx + vw - 40 and vy <= py < vy + vh - 40
        except (OSError, AttributeError):
            return True

    try:
        x, y = json.load(open(POS_FILE))
        if not on_screen(x, y):
            x, y = 60, 60
    except (OSError, ValueError, TypeError):
        x, y = 60, 60
    view = load_view()
    set_lang(view["lang"])
    class Wrapped(list):
        """Labels that wrap: (widget, pad), kept with the window being built (ctx) to wrap in its width."""
        def append(self, item):
            super().append(tuple(item) + (ctx["win"],))
    i18n, wrapped = [], Wrapped()                 # (widget, English text, upper), labels that wrap

    def T(widget, text, upper=False):
        """Give a widget translated text, and keep it to re-translate on a language change."""
        i18n.append((widget, text, upper))
        widget.config(text=tr(text).upper() if upper else tr(text))
        return widget

    def fmt(n):
        return f"{int(n):,}" if view["exact"] else fmt_short(n)

    root = tk.Tk()
    root.report_callback_exception = lambda *exc: report_crash("the overlay")
    root.title("SDS Meter")
    root.overrideredirect(True)
    root.attributes("-alpha", view["opacity"] / 100)
    root.attributes("-topmost", True)
    meter.auto_reset = view["auto_reset"]
    meter.boss_mode = view["boss_mode"]
    Meter.show_names = view["player_names"]
    meter.history_dir = meter.history_dir or HISTORY_DIR
    root.configure(bg=BG, highlightthickness=1, highlightbackground=BG)
    root.geometry(f"340x80+{x}+{y}")
    state = {"mode": "done", "detail": None, "drag": None, "players": [], "hit_boxes": [],
             "target": None, "enemy_boxes": [], "enemy_ids": [],
             "locked": True, "err": None, "tick": 0, "tab": "meter",
             "hist": None, "hist_path": None, "dtab": "damage"}

    def D():
        """What the overlay shows: the live fight, or a fight loaded from the history."""
        return state["hist"] or meter
    events = queue.Queue()
    images = {}
    win = OverlayWindow(root, taskbar=True)
    threading.Thread(target=input_thread, args=(events,), daemon=True).start()

    # Each window has its own fonts and layout (L): one resized narrower than its text and icons
    # need gets smaller ones, the others keep theirs. fonts[...] and L[...] are the ones of the
    # window being built or drawn (ctx, set by in_win); "fixed" is for the windows that keep the
    # settings' sizes (watch bar, score card, tour).
    WINS = ("main", "detail", "rot", "hist", "fx", "fixed")
    RESIZABLE = ("main", "detail", "rot", "hist", "fx")
    MIN_H = {"main": 120, "detail": 150, "rot": 140, "hist": 120, "fx": 160}   # px, resized
    ctx = {"win": "main"}

    class PerWindow:
        """fonts / L: one dict per window; reads and writes go to ctx's (of(w): window w's)."""
        def __init__(self, sets):
            self.sets = sets

        def __getitem__(self, k):
            return self.sets[ctx["win"]][k]

        def __setitem__(self, k, v):
            self.sets[ctx["win"]][k] = v

        def update(self, *a, **kw):
            self.sets[ctx["win"]].update(*a, **kw)

        def of(self, w):
            return self.sets[w]

    def in_win(w):
        """Decorator: while the function runs, fonts and L are window w's."""
        def deco(f):
            @functools.wraps(f)
            def run(*a, **kw):
                old, ctx["win"] = ctx["win"], w
                try:
                    return f(*a, **kw)
                finally:
                    ctx["win"] = old
            return run
        return deco

    # named fonts: resizing them resizes every widget and canvas item that uses them
    fonts = PerWindow({w: {"bold": tkfont.Font(root, family="Segoe UI Semibold"),
                           "norm": tkfont.Font(root, family="Segoe UI"),
                           "small": tkfont.Font(root, family="Segoe UI"),
                           "badge": tkfont.Font(root, family="Segoe UI", weight="bold"),
                           "section": tkfont.Font(root, family="Segoe UI", weight="bold"),
                           "icon": tkfont.Font(root, family="Segoe MDL2 Assets"),
                           "title": tkfont.Font(root, family="Segoe UI Semibold")} for w in WINS})
    has_icons = "Segoe MDL2 Assets" in tkfont.families(root)
    L = PerWindow({w: {} for w in WINS})         # layout, from the window's font and icon presets
    sizes = {w: (view["font_size"], view["icon_size"]) for w in WINS}   # (text, icon) preset each uses

    def fs_now():
        return FONT_SIZES[sizes[ctx["win"]][0]]

    def px_now():
        return ICON_SIZES[sizes[ctx["win"]][1]]

    def user_size(w):
        """[w, h] window w was resized to, None while it sizes itself."""
        return view["sizes"].get(w) if w in RESIZABLE else None

    def user_w(w):
        """The width a resized list window (rotation, history, effects) draws its rows in."""
        us = user_size(w)
        return us[0] - 15 if us else None              # its scrollbar and border

    def natural_w(w, text, icon):
        """Window w's width at those presets, as it sizes itself: the narrowest that shows it all."""
        fs, px = FONT_SIZES[text], ICON_SIZES[icon]
        W = int(26 * fs + 3 * px + 52)
        if w == "rot":
            return (ROT_SMALL_COLS * (px + 8) + 2 * PAD + 8 if view["rot_small"] else
                    max(W + 24, 26 * fs + 4 * px + 60)) + 15
        return {"detail": W + 24, "hist": max(W + 24, 24 * fs + 80) + 15,
                "fx": max(W + 24, 26 * fs + 3 * px + 80) + 15}.get(w, W)

    def pick_sizes(w):
        """The presets window w is drawn with: the settings' ones, or, resized narrower than they
        need, both a step smaller at a time down to mini."""
        ti, ii = SIZE_NAMES.index(view["font_size"]), SIZE_NAMES.index(view["icon_size"])
        us = user_size(w)
        while us and (ti or ii) and natural_w(w, SIZE_NAMES[ti], SIZE_NAMES[ii]) > us[0]:
            ti, ii = max(0, ti - 1), max(0, ii - 1)
        return SIZE_NAMES[ti], SIZE_NAMES[ii]

    def min_size(w):
        """The smallest window w can be resized to: everything still shows at the mini presets."""
        return natural_w(w, "mini", "mini"), MIN_H[w]

    def content_w(w):
        """The width window w's wrapping labels wrap in."""
        return user_w(w) if user_w(w) else L.of(w)["W"]

    def apply_sizes():
        set_icon_size(view["icon_size"])
        for w in WINS:
            sizes[w] = pick_sizes(w)
            base, px = FONT_SIZES[sizes[w][0]], ICON_SIZES[sizes[w][1]]
            f, lay = fonts.of(w), L.of(w)
            f["bold"].configure(size=base)
            f["norm"].configure(size=base)
            f["small"].configure(size=max(7, base - 1))
            f["badge"].configure(size=max(7, base - 2))
            f["section"].configure(size=max(7, base - 2))
            f["icon"].configure(size=max(8, base))
            f["title"].configure(size=base + 4)
            lb, ls = f["bold"].metrics("linespace"), f["small"].metrics("linespace")
            portrait = px + 4
            lay.update(W=int(26 * base + 3 * px + 52), lb=lb, ls=ls,
                       ROWH={0: lb + ls + 12, 1: max(portrait + 6, lb + ls + 8), 2: max(px + 6, ls + 10)},
                       HEADH=ls + 10)
            lay["INDENT"] = {0: 0, 1: 8, 2: 8 + portrait // 2 + 4}
            lay.update(DW=lay["W"] + 24, HEROH=max(portrait + 10, lb + ls + 12), SKH=max(px + 10, lb + ls + 12),
                       TILEH=ls + lb + 14)
        if user_size("main"):                          # resized: the rows stretch to its width
            L.of("main")["W"] = user_size("main")[0]
        if user_size("detail"):
            L.of("detail")["DW"] = user_size("detail")[0]
        state["sizes_ver"] = state.get("sizes_ver", 0) + 1
        err_l.config(wraplength=L.of("main")["W"] - 16)
        for wdg, pad, w in wrapped:
            wdg.config(wraplength=content_w(w) - pad)
        canvas.config(width=L.of("main")["W"])
        dcan.config(width=L.of("detail")["DW"])

    def image(path):
        """A PhotoImage, cached; an icon in the icon size of the window being drawn."""
        root_dir = os.path.join(ROOT, "icons") + os.sep
        if path.startswith(root_dir):
            rest = path[len(root_dir):].split(os.sep, 1)
            if len(rest) == 2:
                path = os.path.join(root_dir, sizes[ctx["win"]][1], rest[1])
        if path not in images:
            try:
                images[path] = tk.PhotoImage(file=path)
            except tk.TclError:
                images[path] = None
        return images[path]

    def rrect(c, x0, y0, x1, y1, r, **kw):
        """Rounded rectangle on canvas c (a smoothed polygon)."""
        kw.setdefault("width", 0)
        r = max(0, min(r, (x1 - x0) / 2, (y1 - y0) / 2))
        if r < 1:
            return c.create_rectangle(x0, y0, x1, y1, **kw)
        return c.create_polygon(x0 + r, y0, x1 - r, y0, x1, y0, x1, y0 + r, x1, y1 - r, x1, y1,
                                x1 - r, y1, x0 + r, y1, x0, y1, x0, y1 - r, x0, y0 + r, x0, y0,
                                smooth=True, **kw)

    # ---- title bar: status dot, clock, target | mode switch and buttons
    bar = tk.Frame(root, bg=TOP, padx=4, pady=3)
    bar.pack(fill="x")
    dot = tk.Canvas(bar, width=10, height=10, bg=TOP, highlightthickness=0)
    dot.pack(side="left", padx=(4, 6))
    dot_id = dot.create_oval(1, 1, 9, 9, fill=WARN, width=0)
    title = tk.Label(bar, text="0:00", bg=TOP, fg=FG, font=fonts["bold"])
    title.pack(side="left")

    def btn(glyph, fallback, cmd, parent=None):
        b = tk.Label(parent or bar, text=glyph if has_icons else fallback, bg=TOP, fg=DIM, padx=5,
                     font=fonts["icon"] if has_icons else fonts["norm"], cursor="hand2")
        b.base = DIM
        b.pack(side="right", padx=1)
        b.bind("<Button-1>", lambda e: cmd())
        b.bind("<Enter>", lambda e: b.config(fg=FG))
        b.bind("<Leave>", lambda e: b.config(fg=b.base))
        return b

    def reset():
        if state["hist"] is not None:            # showing a saved fight: back to the live one
            show_fight(None)
            return
        with meter.lock:
            meter.reset()
        apply_sizes()
        state["detail"] = None
        state["target"] = None

    # footer is packed first so it keeps its space when the body is resized
    foot = tk.Frame(root, bg=BG)
    foot.pack(side="bottom", fill="x", padx=8, pady=(2, 6))
    err_l = tk.Label(foot, text="", bg=BG, fg=BAD, font=fonts["small"], anchor="w", justify="left")
    guide = tk.Canvas(foot, bg=BG, highlightthickness=0, height=1)     # the unlocked banner
    guide.pack(fill="x")
    canvas = tk.Canvas(root, bg=BG, highlightthickness=0, height=1)
    canvas.pack(fill="both", expand=True, pady=(6, 2))

    # ---- damage breakdown: its own window, dragged by its header while unlocked
    ctx["win"] = "detail"
    dwin = tk.Toplevel(root)
    dwin.overrideredirect(True)
    dwin.attributes("-alpha", view["opacity"] / 100)
    dwin.attributes("-topmost", True)
    dwin.configure(bg=BG, highlightthickness=1, highlightbackground=BG)
    try:
        dx, dy = json.load(open(DETAIL_POS_FILE))
        dplaced = on_screen(dx, dy)
    except (OSError, ValueError, TypeError):
        dx, dy, dplaced = x + 400, y, False        # put beside the meter when first shown
    dwin.geometry(f"360x200+{dx}+{dy}")
    dov = OverlayWindow(dwin)
    dov.show(False)
    dshown = {"v": False, "placed": dplaced}
    dhead = tk.Frame(dwin, bg=TOP, padx=6, pady=5)
    dhead.pack(fill="x")
    dportrait = tk.Label(dhead, bg=TOP, bd=0)
    dtitle = tk.Frame(dhead, bg=TOP)
    dtitle.pack(side="left")
    dname = tk.Label(dtitle, text="", bg=TOP, fg=FG, font=fonts["bold"], anchor="w")
    dname.pack(anchor="w")
    drank = tk.Label(dtitle, text="", bg=TOP, fg=DIM, font=fonts["small"], anchor="w")
    drank.pack(anchor="w")
    dcan = tk.Canvas(dwin, bg=BG, highlightthickness=0, height=1)
    dcan.pack(fill="both", expand=True, pady=(6, 6))

    def dstart(e):
        state["ddrag"] = (e.x_root - dwin.winfo_x(), e.y_root - dwin.winfo_y())

    def ddrag(e):
        if state.get("ddrag"):
            dwin.geometry(f"+{e.x_root - state['ddrag'][0]}+{e.y_root - state['ddrag'][1]}")

    for w in (dhead, dportrait, dtitle, dname, drank):
        w.bind("<Button-1>", dstart)
        w.bind("<B1-Motion>", ddrag)
        w.bind("<ButtonRelease-1>", lambda e: save_positions())
    dcan.bind("<Button-3>", lambda e: state.update(detail=None))

    # ---- skill rotation (preview): its own scrollable window, opened from your breakdown,
    ctx["win"] = "rot"
    # to look through after a fight. Always takes clicks, also while the meter is locked.
    rwin = tk.Toplevel(root)
    rwin.overrideredirect(True)
    rwin.attributes("-alpha", view["opacity"] / 100)
    rwin.attributes("-topmost", True)
    rwin.configure(bg=BG, highlightthickness=1, highlightbackground=FAINT)
    rwin.geometry("10x10+0+0")
    rov = OverlayWindow(rwin)
    rov.set_locked(False)
    rov.show(False)
    rot = {"open": False, "ver": None, "placed": False, "drag": None, "rows": None}
    rhead = tk.Frame(rwin, bg=TOP, padx=6, pady=5)
    rhead.pack(fill="x")
    rtitle = T(tk.Label(rhead, bg=TOP, fg=FG, font=fonts["bold"], anchor="w"), "Skill rotation")
    rtitle.pack(side="left")
    T(tk.Label(rhead, bg=ACCENT, fg=TOP, font=fonts["badge"], padx=4), "Preview", upper=True).pack(
        side="left", padx=6)
    rsum = tk.Canvas(rwin, bg=BG, highlightthickness=0, height=1)
    rsum.pack(fill="x", pady=(6, 4))
    rbody = tk.Frame(rwin, bg=BG)
    rbody.pack(fill="both", expand=True, pady=(0, 6))
    rcan = tk.Canvas(rbody, bg=BG, highlightthickness=0, height=1)
    rcan.pack(side="left", fill="both", expand=True)
    rbar = tk.Canvas(rbody, bg=BG, width=10, highlightthickness=0)
    rbar.pack(side="right", fill="y", padx=(0, 3))
    ROT_VISIBLE = 12                             # rows shown at once; the rest scrolls

    def rot_start(e):
        rot["drag"] = (e.x_root - rwin.winfo_x(), e.y_root - rwin.winfo_y())

    def rot_drag(e):
        if rot["drag"]:
            rwin.geometry(f"+{e.x_root - rot['drag'][0]}+{e.y_root - rot['drag'][1]}")

    for w in (rhead, rtitle):
        w.bind("<Button-1>", rot_start)
        w.bind("<B1-Motion>", rot_drag)

    def rot_bar():
        """The scrollbar: a thumb on the right, dragged or clicked to jump."""
        rbar.delete("all")
        a, b = rcan.yview()
        if b - a >= 0.999:
            return
        h = rbar.winfo_height()
        rrect(rbar, 2, a * h, 8, max(a * h + 16, b * h), 3, fill=FG if rot.get("bar_hot") else DIM)

    def rot_jump(e):
        a, b = rcan.yview()
        rcan.yview_moveto(e.y / max(1, rbar.winfo_height()) - (b - a) / 2)
        rot_bar()
    rbar.bind("<Button-1>", rot_jump)
    rbar.bind("<B1-Motion>", rot_jump)
    rbar.bind("<Enter>", lambda e: (rot.update(bar_hot=True), rot_bar()))
    rbar.bind("<Leave>", lambda e: (rot.update(bar_hot=False), rot_bar()))

    def rot_wheel(e):
        """The wheel scrolls the rotation or history list under the pointer."""
        w = root.winfo_containing(e.x_root, e.y_root)
        top = w.winfo_toplevel() if w is not None else None
        if top == root and state["tab"] == "meter":   # a resized meter or breakdown taller than it
            canvas.yview_scroll(-1 if e.delta > 0 else 1, "units")
        elif top == dwin:
            dcan.yview_scroll(-1 if e.delta > 0 else 1, "units")
        elif top == rwin:
            rcan.yview_scroll(-1 if e.delta > 0 else 1, "units")
            rot_bar()
        elif top == hwin:
            hcan.yview_scroll(-1 if e.delta > 0 else 1, "units")
            hist_bar()
        elif top == ewin:
            ecan.yview_scroll(-1 if e.delta > 0 else 1, "units")
            eff_bar()
        elif pick["win"] is not None and top == pick["win"]:
            pick["can"].yview_scroll(-1 if e.delta > 0 else 1, "units")
    root.bind_all("<MouseWheel>", rot_wheel, add="+")

    @in_win("rot")
    def rot_tiles(groups, total):
        W, c, tg = int(rcan.cget("width")) + 13, rsum, 4
        c.delete("all")
        casts = sum(g["n"] for g in groups)
        span = groups[-1]["t"] if groups else 0
        linked = sum(g["damage"] for g in groups)
        tiles = ((tr("CASTS"), str(casts)), (tr("TIME"), f"{int(span) // 60}:{int(span) % 60:02d}"),
                 (tr("CASTS/MIN"), f"{casts * 60 / span:.0f}" if span >= 1 else "-"),
                 (tr("DAMAGE"), fmt(linked) + (f"  {100 * linked / total:.0f}%" if total else "")))
        tw = (W - 2 * PAD - 3 * tg) / 4
        for i, (name, val) in enumerate(tiles):
            tx = PAD + i * (tw + tg)
            rrect(c, tx, 0, tx + tw, L["TILEH"], R, fill=CARD)
            c.create_text(tx + 8, 6, text=name, anchor="nw", fill=DIM, font=fonts["section"])
            c.create_text(tx + 8, L["TILEH"] - 6, text=val, anchor="sw", fill=FG, font=fonts["bold"])
        c.config(width=W, height=L["TILEH"])

    @in_win("rot")
    def draw_rot():
        """One row per cast, in order: time into the fight and the gap since the
        previous cast, the skill's icon and name (×n for an attack chain or repeated
        dodges), the damage that cast dealt with its hits and crits, and a bar of it
        against your biggest cast. A tag swap is a band with the hero swapped in."""
        groups, total = D().rotation_groups()
        if view["rot_small"]:
            return draw_rot_small(groups)
        if not rsum.winfo_ismapped():
            rsum.pack(fill="x", pady=(6, 4), before=rbody)
        px = px_now()
        W = user_w("rot") or max(L["DW"], 26 * fs_now() + 4 * px + 60)
        rowh, sw = max(px + 8, L["lb"] + L["ls"] + 10), fonts["bold"].measure("00:00.0") + 10
        c = rcan
        at_end, top = c.yview()[1] >= 0.999, c.yview()[0]
        c.delete("all")
        c.config(width=W)
        rot_tiles(groups, total)
        best = max((g["damage"] for g in groups), default=0) or 1
        y = 0
        for g in groups:
            m, s = divmod(g["t"], 60)
            when = f"{int(m)}:{s:04.1f}"
            ly, sy = y + rowh // 2 - L["ls"] // 2, y + rowh // 2 + L["lb"] // 2
            right = []
            if g["damage"]:
                right = [(fmt(g["damage"]), fonts["bold"], FG),
                         (f"{100 * g['damage'] / total:.0f}%" if total else "", fonts["small"], SUBFG)]
            if g["swap"]:                         # tag swap: a band across, the hero's portrait
                rrect(c, PAD, y, W - PAD, y + rowh, R, fill=CARD)
                rrect(c, PAD, y, PAD + 4, y + rowh, 2, fill=ACCENT)
                c.create_text(PAD + 10, y + rowh // 2, text=when, anchor="w", fill=ACCENT_HI, font=fonts["bold"])
                tx = PAD + 10 + sw
                im = image(g["icon"]) if g.get("icon") else None
                if im is not None:
                    c.create_image(tx, y + rowh // 2, image=im, anchor="w")
                    tx += im.width() + 8
                left = rtext(W - PAD - 8, y + rowh // 2, right, canvas=c)
                c.create_text(tx, y + rowh // 2, text=fit(g["label"], fonts["bold"], left - tx - 4), anchor="w",
                              fill=FG, font=fonts["bold"])
                y += rowh + GAP
                continue
            x0 = PAD + 10
            rrect(c, x0, y, W - PAD, y + rowh, R, fill=PANEL)
            c.create_text(x0 + 8, ly, text=when, anchor="w", fill=SUBFG, font=fonts["norm"])
            if g["gap"] is not None:
                c.create_text(x0 + 8, sy, text=f"+{g['gap']:.1f}s", anchor="w",
                              fill=WARN if g["gap"] >= 2 else DIM, font=fonts["small"])
            tx = x0 + 8 + sw
            im = image(g["icon"]) if g.get("icon") else None
            if im is not None:
                c.create_image(tx, y + rowh // 2, image=im, anchor="w")
                tx += im.width() + 8
            name = g["label"] + (f"  ×{g['n']}" if g["n"] > 1 else "")
            if g["hero"] and not g["key"].startswith("dodge_"):
                name += f"  ·  {g['hero']}"
            nx = tx
            if g.get("bind"):                     # the key it was pressed with
                kh = L["ls"] + 2
                nx += keycap(c, nx, ly - kh // 2, g["bind"], kh) + 6
            left = rtext(W - PAD - 8, ly, right, canvas=c)
            c.create_text(nx, ly, text=fit(name, fonts["norm"], left - nx - 4), anchor="w", fill=FG,
                          font=fonts["norm"])
            if g["hits"]:
                sub = tr("{n} hits" if g["hits"] != 1 else "{n} hit", n=g["hits"]) + "  ·  " + \
                      tr("crit") + f" {100 * g['crits'] / g['hits']:.0f}%"
            else:
                sub = tr("no damage")
            c.create_text(tx, sy, text=fit(sub, fonts["small"], W - PAD - 8 - tx), anchor="w",
                          fill=SUBFG if g["hits"] else DIM, font=fonts["small"])
            if g["damage"]:                       # against your biggest cast
                bx0, bx1 = x0 + 6, W - PAD - 6
                c.create_line(bx0, y + rowh - 3, bx0 + max(2, int((bx1 - bx0) * g["damage"] / best)),
                              y + rowh - 3, fill=ACCENT, width=2)
            y += rowh + GAP
        if not groups:
            rrect(c, PAD, 0, W - PAD, rowh, R, fill=PANEL)
            c.create_text(W // 2, rowh // 2, text=tr("No skills cast yet"), fill=DIM, font=fonts["small"])
            y = rowh + GAP
        rot_finish(W, y, min(max(1, len(groups)), ROT_VISIBLE), rowh + GAP, at_end, top)

    def rot_finish(W, y, shown, step, at_end, top):
        """Scroll region, the visible part (shown steps of step px), back to where it was
        scrolled (or the end), and the window resized only when that changes."""
        us = user_size("rot")
        rcan.config(height=1 if us else shown * step, scrollregion=(0, 0, W, y), yscrollincrement=step)
        rcan.yview_moveto(1.0 if at_end else top)
        if us:                                       # resized: that size, the rows scroll
            rot["rows"] = None
            rwin.geometry(f"{us[0]}x{us[1]}")
        elif rot["rows"] != (shown, W, view["rot_small"]):
            rot["rows"] = (shown, W, view["rot_small"])
            rwin.update_idletasks()
            rwin.geometry(f"{rwin.winfo_reqwidth()}x{rwin.winfo_reqheight()}")
        rwin.after_idle(rot_bar)

    ROT_SMALL_COLS, ROT_SMALL_LINES = 10, 6      # small version: icons a line, lines shown

    @in_win("rot")
    def draw_rot_small(groups):
        """Only the skill icons, in order, wrapping: the same skill cast in a row is one
        icon with the count under it, a tag swap the hero's portrait (outlined), a
        dodge a small pill (no icon)."""
        rsum.pack_forget()
        merged = []
        for g in groups:
            m = merged[-1] if merged else None
            if m and not g["swap"] and not m["swap"] and m["key"] == g["key"] and m["hero"] == g["hero"]:
                m["n"] += g["n"]
            else:
                merged.append(dict(g))
        groups = merged
        px, gap = px_now(), 4
        cell = px + 4 + gap                           # hero portraits are px + 4
        W = user_w("rot") or ROT_SMALL_COLS * cell + 2 * PAD + 8
        iconh, ch = px + 4, fonts["badge"].metrics("linespace")
        keyh = ch + 2                                 # the key, above the icon
        lineh = keyh + iconh + ch + 8                 # key, icon, its count under it
        c = rcan
        at_end, top = c.yview()[1] >= 0.999, c.yview()[0]
        c.delete("all")
        c.config(width=W)
        x, y, x1 = PAD + 4, 0, W - PAD - 4
        for g in groups:
            im = image(g["icon"]) if g.get("icon") else None
            body = im.width() if im is not None else fonts["badge"].measure(g["label"]) + 10
            kw = fonts["badge"].measure(g["bind"]) + 8 if g.get("bind") else 0
            body = max(body, kw)
            if x + body > x1 and x > PAD + 4:
                x, y = PAD + 4, y + lineh
            cy = y + 2 + keyh + 2 + iconh // 2
            if im is not None:
                ix = x + (body - im.width()) // 2         # centred under its key
                c.create_image(ix, cy, image=im, anchor="w")
                if g["swap"]:
                    h2 = im.height() // 2
                    c.create_rectangle(ix - 1, cy - h2 - 1, ix + im.width(), cy + h2, outline=ACCENT, width=1)
            else:
                rrect(c, x, cy - L["ls"] // 2 - 1, x + body, cy + L["ls"] // 2 + 1, 4, fill=FAINT)
                c.create_text(x + body // 2, cy, text=g["label"], fill=FG, font=fonts["badge"])
            if g.get("bind"):                        # the key, on its own line above the icon
                kx = x + (body - kw) // 2
                rrect(c, kx, y + 2, kx + kw, y + 2 + keyh, 3, fill=TOP, outline=FAINT, width=1)
                c.create_text(kx + kw / 2, y + 2 + keyh / 2, text=g["bind"], fill=SUBFG, font=fonts["badge"])
            if g["n"] > 1:                           # the count, under the icon
                c.create_text(x + body // 2, cy + iconh // 2 + 1, text=f"×{g['n']}", anchor="n", fill=ACCENT_HI,
                              font=fonts["badge"])
            x += body + gap
        if not groups:
            c.create_text(W // 2, lineh // 2, text=tr("No skills cast yet"), fill=DIM, font=fonts["small"])
        lines = y // lineh + 1
        rot_finish(W, y + lineh, min(lines, ROT_SMALL_LINES), lineh, at_end, top)

    def toggle_rot(show=None):
        show = not rot["open"] if show is None else show
        if show == rot["open"]:
            return
        rot["open"], rot["ver"], rot["rows"] = show, None, None
        if show:
            if not rot["placed"]:                 # first time: beside the breakdown, or the meter
                beside = dwin if dshown["v"] else root
                beside.update_idletasks()
                rwin.geometry(f"+{beside.winfo_x() + beside.winfo_width() + 10}+{beside.winfo_y()}")
                rot["placed"] = True
            draw_rot()
            rcan.yview_moveto(0)
            rov.show(True)
            raise_all()
        else:
            rov.show(False)
            close_menu(rhead)
    btn("\uE8BB", "X", lambda: toggle_rot(False), rhead)

    def rot_size():
        """Big (one row per cast, with damage) <-> small (only the skill icons)."""
        view["rot_small"] = not view["rot_small"]
        cfg_vars[(None, "rot_small")].set(view["rot_small"])     # its switch in the wrench menu
        save_view(view)
        rot["ver"], rot["rows"] = None, None
        rsize_b.config(text=rot_glyph())
        draw_rot()
        rcan.yview_moveto(1.0)

    def rot_glyph():
        if has_icons:
            return "\uE740" if view["rot_small"] else "\uE73F"      # full screen / back to window
        return "+" if view["rot_small"] else "-"
    rsize_b = btn(rot_glyph(), rot_glyph(), rot_size, rhead)

    # ---- fight history (preview): every finished fight is saved (Meter.finish_fight); this
    ctx["win"] = "hist"
    # window lists them, loads one into the overlay, and imports / exports fight files
    hwin = tk.Toplevel(root)
    hwin.overrideredirect(True)
    hwin.attributes("-alpha", view["opacity"] / 100)
    hwin.attributes("-topmost", True)
    hwin.configure(bg=BG, highlightthickness=1, highlightbackground=FAINT)
    hwin.geometry("10x10+0+0")
    hov = OverlayWindow(hwin)
    hov.set_locked(False)
    hov.show(False)
    hist = {"open": False, "placed": False, "drag": None, "ver": None, "rows": [], "cache": {}, "size": None}
    hhead = tk.Frame(hwin, bg=TOP, padx=6, pady=5)
    hhead.pack(fill="x")
    htitle = T(tk.Label(hhead, bg=TOP, fg=FG, font=fonts["bold"], anchor="w"), "Fight history")
    htitle.pack(side="left")
    T(tk.Label(hhead, bg=ACCENT, fg=TOP, font=fonts["badge"], padx=4), "Preview", upper=True).pack(
        side="left", padx=6)
    hbtns = tk.Frame(hwin, bg=BG)
    hbtns.pack(fill="x", padx=PAD, pady=(6, 4))
    hbody = tk.Frame(hwin, bg=BG)
    hbody.pack(fill="both", expand=True, pady=(0, 6))
    hcan = tk.Canvas(hbody, bg=BG, highlightthickness=0, height=1)
    hcan.pack(side="left", fill="both", expand=True)
    hbar = tk.Canvas(hbody, bg=BG, width=10, highlightthickness=0)
    hbar.pack(side="right", fill="y", padx=(0, 3))
    HIST_VISIBLE = 10                            # fights shown at once; the rest scrolls

    def hist_start(e):
        hist["drag"] = (e.x_root - hwin.winfo_x(), e.y_root - hwin.winfo_y())

    def hist_drag(e):
        if hist["drag"]:
            hwin.geometry(f"+{e.x_root - hist['drag'][0]}+{e.y_root - hist['drag'][1]}")

    for w in (hhead, htitle):
        w.bind("<Button-1>", hist_start)
        w.bind("<B1-Motion>", hist_drag)

    def hist_bar():
        hbar.delete("all")
        a, b = hcan.yview()
        if b - a >= 0.999:
            return
        h = hbar.winfo_height()
        rrect(hbar, 2, a * h, 8, max(a * h + 16, b * h), 3, fill=FG if hist.get("bar_hot") else DIM)

    def hist_jump(e):
        a, b = hcan.yview()
        hcan.yview_moveto(e.y / max(1, hbar.winfo_height()) - (b - a) / 2)
        hist_bar()
    hbar.bind("<Button-1>", hist_jump)
    hbar.bind("<B1-Motion>", hist_jump)
    hbar.bind("<Enter>", lambda e: (hist.update(bar_hot=True), hist_bar()))
    hbar.bind("<Leave>", lambda e: (hist.update(bar_hot=False), hist_bar()))

    def hbutton(text, cmd):
        b = T(tk.Label(hbtns, bg=FAINT, fg=FG, font=fonts["small"], padx=8, pady=2, cursor="hand2"), text)
        b.pack(side="left", padx=(0, 4))
        b.bind("<Button-1>", lambda e: cmd())
        b.bind("<Enter>", lambda e: b.config(bg=ACCENT, fg=TOP))
        b.bind("<Leave>", lambda e: b.config(bg=FAINT, fg=FG))
        return b

    def show_fight(data, path=None):
        """Show a saved fight (its JSON) in the overlay, or the live one again (None)."""
        if data is None:
            state["hist"], state["hist_path"] = None, None
        else:
            state["hist"], state["hist_path"] = Meter.load_fight(data), path
            state["detail"] = next(iter(state["hist"].me), None)    # straight to your breakdown
        state["target"], rot["ver"], hist["ver"] = None, None, None
        set_tab("meter")

    def with_dialog(ask):
        """A file dialog in front of the always-on-top overlay windows."""
        wins = (root, dwin, rwin, hwin, ewin, wwin)
        for w in wins:
            w.attributes("-topmost", False)
        try:
            return ask()
        finally:
            for w in wins:
                w.attributes("-topmost", True)

    def import_fight():
        from tkinter import filedialog
        path = with_dialog(lambda: filedialog.askopenfilename(
            parent=hwin, title=tr("Import a fight"), initialdir=HISTORY_DIR,
            filetypes=[(tr("SDS Meter fight"), "*.json"), ("*", "*")]))
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                show_fight(json.load(f), path)
        except (OSError, ValueError, KeyError, TypeError) as e:
            state["err"] = tr("Could not open {f}: {e}", f=os.path.basename(path), e=e)

    def export_fight():
        """The fight on screen (a loaded one, or the live one) to a file to share."""
        from tkinter import filedialog
        if state["hist"] is not None:
            data = state["hist"].loaded
        else:
            with meter.lock:
                data = meter.export_fight() if meter.t0 is not None else None
        if data is None:
            state["err"] = tr("No fight to export yet")
            return
        name = re.sub(r"[^\w\- ]+", "", data.get("name") or "").strip() or "fight"
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(data["t0"])) if data.get("t0") else "fight"
        path = with_dialog(lambda: filedialog.asksaveasfilename(
            parent=hwin, title=tr("Export the fight"), defaultextension=".json",
            initialfile=f"{stamp}_{name}.json", filetypes=[(tr("SDS Meter fight"), "*.json")]))
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
        except (OSError, TypeError, ValueError) as e:
            state["err"] = tr("Could not save {f}: {e}", f=os.path.basename(path), e=e)

    hbutton("Import…", import_fight)
    hbutton("Export…", export_fight)
    hbutton("Back to live", lambda: show_fight(None))

    def hist_files():
        """(path, summary) of the saved fights, newest first; summaries cached by mtime."""
        try:
            names = sorted((f for f in os.listdir(HISTORY_DIR) if f.lower().endswith(".json")), reverse=True)
        except OSError:
            names = []
        out = []
        for f in names:
            path = os.path.join(HISTORY_DIR, f)
            try:
                mt = os.path.getmtime(path)
            except OSError:
                continue
            c = hist["cache"].get(path)
            if c is None or c[0] != mt:
                try:
                    with open(path, encoding="utf-8") as fh:
                        d = json.load(fh)
                except (OSError, ValueError):
                    continue
                if not isinstance(d, dict) or d.get("format") != FIGHT_FORMAT:
                    continue
                c = hist["cache"][path] = (mt, {k: d.get(k) for k in ("name", "saved", "duration", "team",
                                                                      "me_damage", "killed", "boss", "t0")})
            out.append((path, c[1]))
        return out

    @in_win("hist")
    def draw_hist():
        """One row per fight, newest first: the live one on top (LIVE), then the saved
        ones: name (boss), when, how long, party damage, your DPS. A click shows it in
        the overlay (the live row: back to live); the one on screen is outlined."""
        live = meter.fight_summary()
        rows = ([(None, live)] if live else []) + hist_files()
        hist["rows"] = rows
        W = user_w("hist") or max(L["DW"], 24 * fs_now() + 80)
        rowh = L["lb"] + L["ls"] + 14
        c = hcan
        at_top = c.yview()[0]
        c.delete("all")
        c.config(width=W)
        y = 0
        for path, d in rows:
            on = (state["hist"] is None) if path is None else path == state["hist_path"]
            rrect(c, PAD, y, W - PAD, y + rowh, R, fill=CARD if on else PANEL)
            if on:
                rrect(c, PAD + 1, y + 1, W - PAD - 1, y + rowh - 1, R, fill="", outline=ACCENT, width=2)
            ly, sy = y + 6 + L["lb"] // 2, y + 8 + L["lb"] + L["ls"] // 2
            dur = d.get("duration") or 0
            when = f"{int(dur) // 60}:{int(dur) % 60:02d}"
            right = rtext(W - PAD - 8, ly, [(when, fonts["bold"], FG)], canvas=c)
            x = PAD + 8
            if path is None:                      # the fight going on now
                chip = tr("LIVE")
                cw = fonts["badge"].measure(chip) + 10
                rrect(c, x, ly - L["ls"] // 2 + 1, x + cw, ly + L["ls"] // 2 - 1, 4, fill=BAD)
                c.create_text(x + cw // 2, ly, text=chip, fill=FG, font=fonts["badge"])
                x += cw + 6
            if d.get("killed"):
                chip = tr("defeated").upper()
                cw = fonts["badge"].measure(chip) + 10
                rrect(c, x, ly - L["ls"] // 2 + 1, x + cw, ly + L["ls"] // 2 - 1, 4, fill=GOOD)
                c.create_text(x + cw // 2, ly, text=chip, fill=TOP, font=fonts["badge"])
                x += cw + 6
            c.create_text(x, ly, text=fit(d.get("name") or tr("Fight"), fonts["bold"], right - x - 6), anchor="w",
                          fill=FG, font=fonts["bold"])
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d["t0"])) if d.get("t0") else d.get("saved")
            sub = f"{when or ''}  ·  {tr('party')} {fmt(d.get('team') or 0)}  ·  " + \
                  f"{tr('you')} {fmt((d.get('me_damage') or 0) / max(1, dur))}/s"
            c.create_text(PAD + 8, sy, text=fit(sub, fonts["small"], W - 2 * PAD - 16), anchor="w", fill=SUBFG,
                          font=fonts["small"])
            y += rowh + GAP
        if not rows:
            rrect(c, PAD, 0, W - PAD, rowh, R, fill=PANEL)
            c.create_text(W // 2, rowh // 2, text=tr("No fights yet"), fill=DIM, font=fonts["small"])
            y = rowh + GAP
        shown = min(max(1, len(rows)), HIST_VISIBLE)
        us = user_size("hist")
        c.config(height=1 if us else shown * (rowh + GAP), scrollregion=(0, 0, W, y), yscrollincrement=rowh + GAP)
        c.yview_moveto(at_top)
        hist["step"] = rowh + GAP
        if us:                                       # resized: that size, the rows scroll
            hist["size"] = None
            hwin.geometry(f"{us[0]}x{us[1]}")
        elif hist["size"] != (shown, W):
            hist["size"] = (shown, W)
            hwin.update_idletasks()
            hwin.geometry(f"{hwin.winfo_reqwidth()}x{hwin.winfo_reqheight()}")
        hwin.after_idle(hist_bar)

    def hist_click(e):
        i = int(hcan.canvasy(e.y) // max(1, hist.get("step", 1)))
        if 0 <= i < len(hist["rows"]):
            path = hist["rows"][i][0]
            if path is None:                      # the live fight
                show_fight(None)
                return
            try:
                with open(path, encoding="utf-8") as f:
                    show_fight(json.load(f), path)
            except (OSError, ValueError, KeyError, TypeError) as err:
                state["err"] = tr("Could not open {f}: {e}", f=os.path.basename(path), e=err)
    hcan.bind("<Button-1>", hist_click)

    def toggle_hist(show=None):
        show = not hist["open"] if show is None else show
        if show == hist["open"]:
            return
        hist["open"], hist["ver"], hist["size"] = show, None, None
        if show:
            if not hist["placed"]:                # first time: beside the meter
                root.update_idletasks()
                hwin.geometry(f"+{root.winfo_x() + root.winfo_width() + 10}+{root.winfo_y()}")
                hist["placed"] = True
            draw_hist()
            hcan.yview_moveto(0)
            hov.show(True)
            raise_all()
        else:
            hov.show(False)
    btn("\uE8BB", "X", lambda: toggle_hist(False), hhead)

    # ---- effects (preview): buffs and debuffs three ways, in one window (Live / Log /
    ctx["win"] = "fx"
    # Uptime), and the watch bar: the effects picked there, with their time left
    ewin = tk.Toplevel(root)
    ewin.overrideredirect(True)
    ewin.attributes("-alpha", view["opacity"] / 100)
    ewin.attributes("-topmost", True)
    ewin.configure(bg=BG, highlightthickness=1, highlightbackground=FAINT)
    ewin.geometry("10x10+0+0")
    eov = OverlayWindow(ewin)
    eov.set_locked(False)
    eov.show(False)
    eff = {"open": False, "placed": False, "drag": None, "ver": None, "tab": "live", "boxes": [], "size": None}
    ehead = tk.Frame(ewin, bg=TOP, padx=6, pady=5)
    ehead.pack(fill="x")
    etitle = T(tk.Label(ehead, bg=TOP, fg=FG, font=fonts["bold"], anchor="w"), "Effects")
    etitle.pack(side="left")
    T(tk.Label(ehead, bg=ACCENT, fg=TOP, font=fonts["badge"], padx=4), "Preview", upper=True).pack(
        side="left", padx=6)
    etabs = tk.Frame(ewin, bg=BG)
    etabs.pack(fill="x", padx=PAD, pady=(6, 2))
    ehint = T(tk.Label(ewin, bg=BG, fg=DIM, font=fonts["small"], anchor="w", justify="left"),
              "Click an effect to watch it (★): while it is on, it shows on the watch bar with its time left.")
    ehint.pack(fill="x", padx=PAD + 2, pady=(0, 4))
    wrapped.append((ehint, 20))
    ebody = tk.Frame(ewin, bg=BG)
    ebody.pack(fill="both", expand=True, pady=(0, 6))
    ecan = tk.Canvas(ebody, bg=BG, highlightthickness=0, height=1)
    ecan.pack(side="left", fill="both", expand=True)
    ebar = tk.Canvas(ebody, bg=BG, width=10, highlightthickness=0)
    ebar.pack(side="right", fill="y", padx=(0, 3))
    EFF_VISIBLE = 12                              # rows shown at once; the rest scrolls
    ETABS = (("live", "Live"), ("log", "Log"), ("uptime", "Uptime"))

    def eff_start(e):
        eff["drag"] = (e.x_root - ewin.winfo_x(), e.y_root - ewin.winfo_y())

    def eff_drag(e):
        if eff["drag"]:
            ewin.geometry(f"+{e.x_root - eff['drag'][0]}+{e.y_root - eff['drag'][1]}")

    for w in (ehead, etitle):
        w.bind("<Button-1>", eff_start)
        w.bind("<B1-Motion>", eff_drag)

    def eff_bar():
        ebar.delete("all")
        a, b = ecan.yview()
        if b - a >= 0.999:
            return
        h = ebar.winfo_height()
        rrect(ebar, 2, a * h, 8, max(a * h + 16, b * h), 3, fill=FG if eff.get("bar_hot") else DIM)

    def eff_jump(e):
        a, b = ecan.yview()
        ecan.yview_moveto(e.y / max(1, ebar.winfo_height()) - (b - a) / 2)
        eff_bar()
    ebar.bind("<Button-1>", eff_jump)
    ebar.bind("<B1-Motion>", eff_jump)
    ebar.bind("<Enter>", lambda e: (eff.update(bar_hot=True), eff_bar()))
    ebar.bind("<Leave>", lambda e: (eff.update(bar_hot=False), eff_bar()))

    eff_btns = {}

    def eff_paint_btns():
        for key, b in eff_btns.items():
            on = eff["tab"] == key
            b.config(bg=ACCENT if on else FAINT, fg=TOP if on else FG)

    def eff_pick(key):
        eff["tab"] = key
        ecan.yview_moveto(0)
        eff["ver"], eff["size"] = None, None
        eff_paint_btns()
        draw_eff()

    for key, text in ETABS:                       # hidden effects and the watch bar: its wrench menu
        b = T(tk.Label(etabs, font=fonts["small"], padx=8, pady=2, cursor="hand2"), text)
        b.pack(side="left", padx=(0, 4))
        b.bind("<Button-1>", lambda e, k=key: eff_pick(k))
        eff_btns[key] = b
    eff_paint_btns()
    pick_b = T(tk.Label(etabs, bg=FAINT, fg=FG, font=fonts["small"], padx=8, pady=2, cursor="hand2"),
               "Choose effects ▾")
    pick_b.pack(side="right", padx=(0, 4))


    def fx_icon(c, x, cy, r, size):
        """The effect's icon (its buff icon, else the icon of the skill that put it on), else
        a ? tile; a boss's ultimate (watch bar) a red ! tile. Returns its width."""
        im = image(r["icon"]) if r.get("icon") else None
        if im is not None:
            c.create_image(x, cy, image=im, anchor="w")
            return im.width()
        ult = r["key"] == "ult"
        rrect(c, x, cy - size // 2, x + size, cy + size // 2, 5, fill=BAD if ult else FAINT,
              outline=ENEMY_EDGE if ult else DIM, width=1)
        c.create_text(x + size // 2, cy, text="!" if ult else "?", fill=FG if ult else SUBFG, font=fonts["title"])
        return size

    def fx_row(c, W, y, r, right, sub, frac=None, color=ACCENT, chip=None):
        """One effect row: star (watched), icon, name, a line under it, a value on the
        right, and a bar (frac). The row is clickable: it toggles watching the effect."""
        h, x0, x1 = L["SKH"], PAD, W - PAD
        rrect(c, x0, y, x1, y + h, R, fill=PANEL)
        cy = y + (h - 4) // 2
        watched = r["key"] in view["watch"]
        c.create_text(x0 + 8, cy, text="★" if watched else "☆", anchor="w", fill=ACCENT if watched else DIM,
                      font=fonts["norm"])
        tx = x0 + 8 + fonts["norm"].measure("★") + 6
        tx += fx_icon(c, tx, cy, r, px_now()) + 8
        ly, sy = cy - L["ls"] // 2, cy + L["lb"] // 2
        left = rtext(x1 - 8, ly, [(right, fonts["bold"], FG)], canvas=c)
        nx = tx
        if chip:
            cw = fonts["badge"].measure(chip) + 10
            rrect(c, nx, ly - L["ls"] // 2 + 1, nx + cw, ly + L["ls"] // 2 - 1, 4, fill=ACCENT)
            c.create_text(nx + cw // 2, ly, text=chip, fill=TOP, font=fonts["badge"])
            nx += cw + 6
        c.create_text(nx, ly, text=fit(r["label"], fonts["norm"], left - nx - 4), anchor="w", fill=FG,
                      font=fonts["norm"])
        c.create_text(tx, sy, text=fit(sub, fonts["small"], x1 - 8 - tx), anchor="w", fill=SUBFG,
                      font=fonts["small"])
        if frac is not None:
            bx0, bx1 = x0 + 6, x1 - 6
            c.create_line(bx0, y + h - 3, bx1, y + h - 3, fill=FAINT, width=2)
            c.create_line(bx0, y + h - 3, bx0 + max(2, int((bx1 - bx0) * max(0.0, min(1.0, frac)))), y + h - 3,
                          fill=color, width=2)
        eff["boxes"].append((y, y + h, r["key"]))
        return y + h + GAP

    def fx_header(c, y, text, color):
        c.create_text(PAD + 4, y, text=text.upper(), anchor="nw", fill=color, font=fonts["section"])
        return y + L["ls"] + 4

    def fx_time(t):
        sign, t = ("-" if t <= -0.05 else ""), abs(t)
        return f"{sign}{int(t) // 60}:{t % 60:04.1f}"

    @in_win("fx")
    def draw_eff():
        """The Effects window's tab: Live (on whom, now), Log (by caster -> target, in
        order) or Uptime (for the breakdown's player, or you)."""
        src, c = D(), ecan
        W = user_w("fx") or max(L["DW"], 26 * fs_now() + 3 * px_now() + 80)
        at_end, top = c.yview()[1] >= 0.999, c.yview()[0]
        c.delete("all")
        c.config(width=W)
        eff["boxes"] = []
        y, hidden = 0, view["fx_hidden"]
        if eff["tab"] == "live":
            for tg, label, party, rows in src.effects_live(hidden):
                y = fx_header(c, y, tr("On {t}", t=label), GOOD if party else BAD)
                for r in rows:
                    y = fx_row(c, W, y, r, f"{r['left']:.1f}s", tr("by {p}", p=r["who"]) + f"  ·  {r['total']:.1f}s",
                               r["left"] / max(0.1, r["total"]), GOOD if party else ENEMY_EDGE)
                y += 6
            empty = tr("No effects active right now")
        elif eff["tab"] == "log":
            for caster, target, rows in src.effects_log(hidden):
                y = fx_header(c, y, f"{caster}  →  {target}", ACCENT)
                for r in rows:
                    sub = fx_time(r["t"]) + "  ·  " + tr("lasted {s}s", s=f"{r['dur']:.1f}")
                    if r["active"]:
                        sub += "  ·  " + tr("on now")
                    y = fx_row(c, W, y, r, f"{r['dur']:.1f}s", sub, chip=tr("refreshed").upper() if r["refreshed"] else None)
                y += 6
            empty = tr("No effects yet")
        else:
            aid = state["detail"] if state["detail"] in (src.me | src.players) else next(iter(src.me), None)
            if aid is not None:
                label = src.label(aid)
                secs = src.buff_uptime(aid, state["target"] if state["mode"] == "done" else None, hidden)
                for sec, title, color in (("on", tr("Effects on {p}", p=label), GOOD),
                                          ("applied", tr("Effects {p} applied", p=label), ACCENT),
                                          ("enemy", tr("Debuffs from enemies"), BAD)):
                    rows = secs.get(sec)
                    if not rows:
                        continue
                    y = fx_header(c, y, title, color)
                    for r in rows[:view["max_rows"]]:
                        sub = tr("applied {n}×", n=r["n"]) + "  ·  " + tr("avg {s}s", s=f"{r['avg']:.1f}") + \
                            "  ·  " + tr("{s}s in total", s=f"{r['total']:.0f}")
                        y = fx_row(c, W, y, r, f"{100 * r['uptime']:.0f}%", sub, r["uptime"], color)
                    y += 6
            empty = tr("No effects yet")
        if y == 0:
            rrect(c, PAD, 0, W - PAD, L["SKH"], R, fill=PANEL)
            c.create_text(W // 2, L["SKH"] // 2, text=empty, fill=DIM, font=fonts["small"])
            y = L["SKH"] + GAP
        step = L["SKH"] + GAP
        shown = max(3, min(EFF_VISIBLE, y // step + 1))
        us = user_size("fx")
        c.config(height=1 if us else shown * step, scrollregion=(0, 0, W, y), yscrollincrement=step)
        c.yview_moveto(1.0 if at_end and eff["tab"] == "log" else top)
        if us:                                       # resized: that size, the rows scroll
            eff["size"] = None
            ewin.geometry(f"{us[0]}x{us[1]}")
        elif eff["size"] != (shown, W):
            eff["size"] = (shown, W)
            ewin.update_idletasks()
            ewin.geometry(f"{ewin.winfo_reqwidth()}x{ewin.winfo_reqheight()}")
        ewin.after_idle(eff_bar)

    def eff_click(e):
        """A click on an effect row: watch it on the watch bar / stop watching it."""
        y = ecan.canvasy(e.y)
        for y0, y1, key in eff["boxes"]:
            if y0 <= y < y1:
                if key in view["watch"]:
                    view["watch"].remove(key)
                else:
                    view["watch"].append(key)
                save_view(view)
                eff["ver"] = None
                draw_eff()
                return
    ecan.bind("<Button-1>", eff_click)

    def toggle_eff(show=None):
        show = not eff["open"] if show is None else show
        if show == eff["open"]:
            return
        eff["open"], eff["ver"], eff["size"] = show, None, None
        if show:
            if not eff["placed"]:                 # first time: beside the meter
                root.update_idletasks()
                ewin.geometry(f"+{root.winfo_x() + root.winfo_width() + 10}+{root.winfo_y()}")
                eff["placed"] = True
            draw_eff()
            ecan.yview_moveto(0)
            eov.show(True)
            raise_all()
        else:
            eov.show(False)
            close_picker()
            close_menu(ehead)
    btn("\uE8BB", "X", lambda: toggle_eff(False), ehead)

    # the effect picker: every effect by its icon (hover: its name), to watch one before it
    # is ever on; a dropdown under "Choose effects", with a search box
    pick = {"win": None, "cells": [], "tip": None, "all": None, "lang": None}
    PICK_COLS, PICK_LINES = 12, 8

    def pick_items():
        """One entry per effect (in-game English name) with its name in the meter's
        language and its icon; cached per language."""
        if pick["lang"] != view["lang"]:
            first = {}
            for tid in BUFF_EN:
                first.setdefault(buff_key(tid), tid)
            pick["all"] = [dict(key=key, label=buff_name(tid),
                                icon=_icon("buff_" + BUFF_ICONS[tid]) if tid in BUFF_ICONS else None)
                           for key, tid in first.items()]
            pick["lang"] = view["lang"]
        return pick["all"]

    @in_win("fx")
    def pick_tip(text=None, x=0, y=0):
        """The name of the icon under the pointer, beside it."""
        if text is None:
            if pick["tip"] is not None:
                pick["tip"].destroy()
                pick["tip"] = None
            return
        if pick["tip"] is None:
            pick["tip"] = tk.Toplevel(root)
            pick["tip"].overrideredirect(True)
            pick["tip"].attributes("-topmost", True)
            tk.Label(pick["tip"], bg=TOP, fg=FG, font=fonts["small"], padx=6, pady=2,
                     highlightthickness=1, highlightbackground=FAINT).pack()
        pick["tip"].winfo_children()[0].config(text=text)
        pick["tip"].geometry(f"+{x + 14}+{y + 18}")
        pick["tip"].lift()                           # above the picker, which re-raises itself
        pick["tip"].attributes("-topmost", True)

    @in_win("fx")
    def draw_picker(*_):
        """The icon grid: watched ones first (outlined, ★), then by name; filtered by the
        search box (name in the meter's language or in English)."""
        if pick["win"] is None:
            return
        c, q = pick["can"], pick["query"].get().strip().lower()
        items = [r for r in pick_items() if not q or q in r["label"].lower() or q in r["key"].lower()]
        items.sort(key=lambda r: (r["key"] not in view["watch"], r["label"].lower()))
        px = px_now()
        cell = px + 10
        c.delete("all")
        pick["cells"] = []
        for i, r in enumerate(items):
            x, y = 4 + (i % PICK_COLS) * cell, 4 + (i // PICK_COLS) * cell
            fx_icon(c, x + 5, y + cell // 2, r, px)
            if r["key"] in view["watch"]:
                c.create_rectangle(x + 2, y + 2, x + cell - 2, y + cell - 2, outline=ACCENT, width=2)
                c.create_text(x + cell - 3, y + 3, text="★", anchor="ne", fill=ACCENT, font=fonts["badge"])
            pick["cells"].append((x, y, x + cell, y + cell, r))
        if not items:
            c.create_text(PICK_COLS * cell // 2, cell // 2, text=tr("No effects found"), fill=DIM,
                          font=fonts["small"])
        rows = max(1, (len(items) + PICK_COLS - 1) // PICK_COLS)
        c.config(width=PICK_COLS * cell + 8, height=min(rows, PICK_LINES) * cell + 8,
                 scrollregion=(0, 0, PICK_COLS * cell + 8, rows * cell + 8), yscrollincrement=cell)
        pick["count"].config(text=tr("{n} effects", n=len(items)) + "  ·  " +
                             tr("{n} watched", n=len(view["watch"])))

    def pick_cell(e):
        x, y = pick["can"].canvasx(e.x), pick["can"].canvasy(e.y)
        return next((r for x0, y0, x1, y1, r in pick["cells"] if x0 <= x < x1 and y0 <= y < y1), None)

    def pick_hover(e):
        r = pick_cell(e)
        pick_tip((r["label"] + ("  ★" if r["key"] in view["watch"] else "")) if r else None, e.x_root, e.y_root)

    def pick_click(e):
        r = pick_cell(e)
        if r is None:
            return
        if r["key"] in view["watch"]:
            view["watch"].remove(r["key"])
        else:
            view["watch"].append(r["key"])
        save_view(view)
        eff["ver"] = None
        draw_picker()
        pick_hover(e)

    def close_picker(e=None):
        pick_tip(None)
        if pick["win"] is not None:
            pick["win"].destroy()
            pick["win"] = None
        pick_b.config(text=tr("Choose effects ▾"), bg=FAINT, fg=FG)

    @in_win("fx")
    def open_picker():
        """The dropdown under the button: search box, icon grid, how many are watched."""
        if pick["win"] is not None:
            close_picker()
            return
        pw = pick["win"] = tk.Toplevel(root)
        pw.overrideredirect(True)
        pw.attributes("-topmost", True)
        pw.attributes("-alpha", view["opacity"] / 100)
        pw.configure(bg=PANEL, highlightthickness=1, highlightbackground=ACCENT)
        top = tk.Frame(pw, bg=PANEL)
        top.pack(fill="x", padx=6, pady=(6, 4))
        T(tk.Label(top, bg=PANEL, fg=SUBFG, font=fonts["small"]), "Search").pack(side="left", padx=(0, 6))
        pick["query"] = tk.StringVar()
        ent = tk.Entry(top, textvariable=pick["query"], bg=CARD, fg=FG, insertbackground=FG, relief="flat",
                       font=fonts["norm"], highlightthickness=1, highlightbackground=FAINT, highlightcolor=ACCENT)
        ent.pack(side="left", fill="x", expand=True)
        x_b = tk.Label(top, text="✕", bg=PANEL, fg=DIM, font=fonts["norm"], padx=6, cursor="hand2")
        x_b.pack(side="right")
        x_b.bind("<Button-1>", close_picker)
        body = tk.Frame(pw, bg=PANEL)
        body.pack(fill="both", expand=True, padx=4)
        pick["can"] = tk.Canvas(body, bg=PANEL, highlightthickness=0)
        pick["can"].pack(side="left")
        pick["count"] = tk.Label(pw, bg=PANEL, fg=DIM, font=fonts["small"], anchor="w")
        pick["count"].pack(fill="x", padx=8, pady=(2, 6))
        T(tk.Label(pw, bg=PANEL, fg=DIM, font=fonts["small"], anchor="w", justify="left"),
          "Hover an icon to see its name; click it to watch that effect (★).").pack(fill="x", padx=8,
                                                                                    pady=(0, 6))
        pick["can"].bind("<Motion>", pick_hover)
        pick["can"].bind("<Leave>", lambda e: pick_tip(None))
        pick["can"].bind("<Button-1>", pick_click)
        pick["query"].trace_add("write", draw_picker)
        pw.bind("<Escape>", close_picker)
        draw_picker()
        pick_b.config(text=tr("Choose effects ▴"), bg=ACCENT, fg=TOP)
        pw.lift()
        pw.update_idletasks()
        pw.geometry(f"+{max(0, pick_b.winfo_rootx() + pick_b.winfo_width() - pw.winfo_reqwidth())}"
                    f"+{pick_b.winfo_rooty() + pick_b.winfo_height() + 4}")
        ent.focus_force()
    pick_b.bind("<Button-1>", lambda e: open_picker())

    # the watch bar: a small always-on-top strip with the watched effects that are on
    ctx["win"] = "fixed"
    wwin = tk.Toplevel(root)
    wwin.overrideredirect(True)
    wwin.attributes("-alpha", view["opacity"] / 100)
    wwin.attributes("-topmost", True)
    wwin.configure(bg=BG, highlightthickness=1, highlightbackground=BG)
    wcan = tk.Canvas(wwin, bg=BG, highlightthickness=0, width=10, height=10)
    wcan.pack()
    try:
        wx, wy = json.load(open(WATCH_POS_FILE))
        wplaced = on_screen(wx, wy)
    except (OSError, ValueError, TypeError):
        wx, wy, wplaced = 0, 0, False
    wwin.geometry(f"10x10+{wx}+{wy}")
    wov = OverlayWindow(wwin)
    wov.show(False)
    watch = {"shown": False, "placed": wplaced, "drag": None, "size": None}

    def watch_start(e):
        watch["drag"] = (e.x_root - wwin.winfo_x(), e.y_root - wwin.winfo_y())

    def watch_drag(e):
        if watch["drag"]:
            wwin.geometry(f"+{e.x_root - watch['drag'][0]}+{e.y_root - watch['drag'][1]}")

    def watch_save(e=None):
        try:
            json.dump([wwin.winfo_x(), wwin.winfo_y()], open(WATCH_POS_FILE, "w"))
        except OSError:
            pass
    wcan.bind("<Button-1>", watch_start)
    wcan.bind("<B1-Motion>", watch_drag)
    wcan.bind("<ButtonRelease-1>", watch_save)

    @in_win("fixed")
    def draw_watch():
        """Every watched effect, in the order they were picked: on, its icon, time left (and a
        bar of it) and name, green on you, blue on a teammate, red on an enemy; off, dimmed.
        A charging boss ultimate first. Hidden when nothing is watched."""
        items = [dict(key="ult", label=tr("Ultimate"), icon=None, left=u["left"], total=u["total"], mine=False,
                      target=u["boss"]) for u in meter.ult_status() if u["charging"]]
        active = meter.effects_watch(set(view["watch"]))
        meta = {r["key"]: r for r in pick_items()}
        for key in view["watch"]:
            on = [r for r in active if r["key"] == key]
            if not on:                               # off: still there, dimmed
                m = meta.get(key) or dict(label=tr("Buff #{n}", n=key.lstrip("#")) + f" ({tr('hidden')})",
                                          icon=None)
                on = [dict(key=key, label=m["label"], icon=m["icon"], left=0.0, total=1.0, mine=False,
                           target=None, off=True)]
            items += on
        if not items and state["tab"] == "windows":  # windows tab open: an empty bar, to drag into place
            items = [dict(key="placeholder", label=tr("Watch bar"), icon=None, left=0.0, total=1.0, mine=False,
                          target=None, off=True)]
        if not items or not view["watch_bar"]:       # nothing to show, or turned off
            if watch["shown"]:
                watch["shown"] = False
                wov.show(False)
            return
        c, px = wcan, px_now() + 8
        c.delete("all")
        x, cells = 6, []
        for r in items:
            name = r["label"] if len(r["label"]) <= 14 else r["label"][:13] + "…"
            w = max(px, fonts["badge"].measure(name)) + 8
            cells.append((r, name, w))
        H = 6 + px + 4 + L["ls"] + fonts["badge"].metrics("linespace") + 8
        for r, name, w in cells:
            off = r.get("off")
            color = GOOD if r["mine"] else (BAD if r["target"] not in meter.players else "#5b9cff")
            cx = x + w // 2
            rrect(c, x, 2, x + w, H - 2, R, fill=PANEL)
            fx_icon(c, cx - px // 2 + 4, 6 + px // 2, r, px - 8)
            by = 6 + px + 1                          # time left, as a bar
            c.create_line(x + 4, by, x + w - 4, by, fill=FAINT, width=3)
            if off:                                  # not on: the icon dimmed, no time
                c.create_rectangle(x + 2, 4, x + w - 2, by - 2, fill=PANEL, stipple="gray50", outline="")
                c.create_text(cx, by + 3, text="–", anchor="n", fill=DIM, font=fonts["bold"])
            else:
                c.create_line(x + 4, by, x + 4 + max(2, int((w - 8) * r["left"] / max(0.1, r["total"]))), by,
                              fill=color, width=3)
                c.create_text(cx, by + 3, text=f"{r['left']:.1f}s", anchor="n", fill=FG, font=fonts["bold"])
            c.create_text(cx, by + 3 + L["ls"], text=name, anchor="n", fill=DIM if off else SUBFG,
                          font=fonts["badge"])
            x += w + 4
        Wd = x + 2
        c.config(width=Wd, height=H)
        if watch["size"] != (Wd, H):
            watch["size"] = (Wd, H)
            if not watch["placed"]:                  # first time: above the meter
                root.update_idletasks()
                pos = (root.winfo_x(), max(0, root.winfo_y() - H - 8))
                wwin.geometry(f"{Wd}x{H}+{pos[0]}+{pos[1]}")
                wov.move(*pos)                       # Tk ignores the position of the hidden window
                watch["placed"] = True
            else:
                wwin.geometry(f"{Wd}x{H}")
        if not watch["shown"]:
            watch["shown"] = True
            wov.show(True)
            wov.set_locked(state["locked"])
            raise_all()

    # the guild boss score: a small always-on-top card (Cfg > Windows), shown during a run
    swin = tk.Toplevel(root)
    swin.overrideredirect(True)
    swin.attributes("-alpha", view["opacity"] / 100)
    swin.attributes("-topmost", True)
    swin.configure(bg=BG, highlightthickness=1, highlightbackground=BG)
    scan = tk.Canvas(swin, bg=BG, highlightthickness=0, width=10, height=10)
    scan.pack()
    try:
        scx, scy = json.load(open(SCORE_POS_FILE))
        splaced = on_screen(scx, scy)
    except (OSError, ValueError, TypeError):
        scx, scy, splaced = 0, 0, False
    swin.geometry(f"10x10+{scx}+{scy}")
    sov = OverlayWindow(swin)
    sov.show(False)
    score = {"shown": False, "placed": splaced, "drag": None, "size": None}

    def score_start(e):
        score["drag"] = (e.x_root - swin.winfo_x(), e.y_root - swin.winfo_y())

    def score_drag(e):
        if score["drag"]:
            swin.geometry(f"+{e.x_root - score['drag'][0]}+{e.y_root - score['drag'][1]}")

    def score_save(e=None):
        try:
            json.dump([swin.winfo_x(), swin.winfo_y()], open(SCORE_POS_FILE, "w"))
        except OSError:
            pass
    scan.bind("<Button-1>", score_start)
    scan.bind("<B1-Motion>", score_drag)
    scan.bind("<ButtonRelease-1>", score_save)

    @in_win("fixed")
    def draw_score():
        """The guild ranking's score: live, and the server's. Outside a guild boss run an empty
        card (it stays where it was put); hidden only when turned off."""
        sc = D().boss_score() if view["gb_score"] else None
        if not sc and view["gb_score"]:
            sc = "placeholder"
        if not score["placed"] and state["tick"] < 3:   # placed under the meter: once it has its size
            sc = None
        if not sc:
            if score["shown"]:
                score["shown"] = False
                sov.show(False)
            return
        final = sc != "placeholder" and sc["final"] is not None
        # the live guess rounded up, as the server's scores came out (5,720.3 -> 5,721); round(…, 6)
        # first so float noise on a whole number (12,210.0000001) doesn't add a point
        value = "–" if sc == "placeholder" else f"{sc['final']:,}" if final else \
            f"≈ {math.ceil(round(sc['est'], 6)):,}"
        if sc == "placeholder":
            sub = tr("shows during a guild boss run")
        elif final:
            sub = tr("final score of the run")
        elif sc["server"] is not None:
            sub = tr("server: {s} at Lv {n}", s=f"{sc['server']:,}", n=sc["level"])
        else:
            sub = ""
        c, chip, name = scan, tr("SCORE"), tr("Guild ranking")
        cw = fonts["badge"].measure(chip) + 10
        Wd = 2 * PAD + max(16 + cw + 6 + fonts["bold"].measure(name) + 12 + fonts["title"].measure(value),
                           16 + fonts["small"].measure(sub))
        H = L["lb"] + L["ls"] + 14
        x0, x1 = 0, Wd
        ty1, ty2 = 5 + L["lb"] // 2, 6 + L["lb"] + L["ls"] // 2
        c.delete("all")
        rrect(c, x0, 0, x1, H, R, fill=PANEL)
        rrect(c, x0 + 8, ty1 - L["ls"] // 2 + 1, x0 + 8 + cw, ty1 + L["ls"] // 2 - 1, 4, fill="#5b9cff")
        c.create_text(x0 + 8 + cw // 2, ty1, text=chip, fill=TOP, font=fonts["badge"])
        c.create_text(x0 + 8 + cw + 6, ty1, text=name, anchor="w", fill=FG, font=fonts["bold"])
        c.create_text(x1 - 8, ty1, text=value, anchor="e", fill=GOOD if final else ACCENT_HI, font=fonts["title"])
        c.create_text(x0 + 8, ty2, text=sub, anchor="w", fill=GOOD if final else SUBFG, font=fonts["small"])
        c.config(width=Wd, height=H)
        if score["size"] != (Wd, H):
            score["size"] = (Wd, H)
            if not score["placed"]:                  # first time: under the meter
                root.update_idletasks()
                pos = (root.winfo_x(), root.winfo_y() + root.winfo_height() + 8)
                swin.geometry(f"{Wd}x{H}+{pos[0]}+{pos[1]}")
                sov.move(*pos)                       # Tk ignores the position of the hidden window
                score["placed"] = True
            else:
                swin.geometry(f"{Wd}x{H}")
        if not score["shown"]:
            score["shown"] = True
            sov.show(True)
            sov.set_locked(state["locked"])
            raise_all()

    # ---- config tab and the windows' wrench menus: cards of settings with toggle switches
    ctx["win"] = "main"
    cfg = tk.Frame(root, bg=BG)
    wtab = tk.Frame(root, bg=BG)                         # the windows tab: every window, open / closed
    cfg_vars = {}
    cur = {"card": None, "tab": cfg}

    def changed():
        for (who, key), v in cfg_vars.items():
            if who:
                view[who][key] = v.get()
            else:
                view[key] = v.get()
        meter.boss_mode = view["boss_mode"]
        Meter.show_names = view["player_names"]
        rsize_b.config(text=rot_glyph())                 # the rotation's size, also switched in its wrench
        if rot["open"] and rot["rows"] and rot["rows"][2] != view["rot_small"]:
            rot["ver"], rot["rows"] = None, None
            draw_rot()
        eff["ver"], eff["size"] = None, None
        save_view(view)

    def section(text):
        T(tk.Label(cur["tab"], bg=BG, fg=ACCENT, font=fonts["section"], anchor="w"), text,
          upper=True).pack(fill="x", padx=PAD + 4, pady=(8, 3))
        card = tk.Frame(cur["tab"], bg=CARD, padx=10, pady=4)
        card.pack(fill="x", padx=PAD)
        cur["card"] = card

    def row_frame():
        row = tk.Frame(cur["card"], bg=CARD)
        row.pack(fill="x", pady=3)
        return row

    def paint_switch(sw, on):
        sw.delete("all")
        rrect(sw, 1, 1, 33, 17, 8, fill=ACCENT if on else FAINT)
        kx = 25 if on else 9
        sw.create_oval(kx - 6, 3, kx + 6, 15, fill=TOP if on else SUBFG, width=0)

    def check(text, who, key):
        v = tk.BooleanVar(value=view[who][key] if who else view[key])
        cfg_vars[(who, key)] = v
        row = row_frame()
        lab = T(tk.Label(row, bg=CARD, fg=FG, font=fonts["norm"], anchor="w", justify="left",
                         cursor="hand2"), text)
        lab.pack(side="left", fill="x", expand=True)
        wrapped.append((lab, 100))
        sw = tk.Canvas(row, width=34, height=18, bg=CARD, highlightthickness=0, cursor="hand2")
        sw.pack(side="right")

        def paint(*_):
            paint_switch(sw, v.get())

        def flip(e=None):
            v.set(not v.get())
            changed()
        v.trace_add("write", paint)
        for w in (row, lab, sw):
            w.bind("<Button-1>", flip)
        paint()

    def stepper(text, key, lo, hi, step=1, on_change=None):
        row = row_frame()
        lab = T(tk.Label(row, bg=CARD, fg=FG, font=fonts["norm"], anchor="w", justify="left"), text)
        lab.pack(side="left")
        wrapped.append((lab, 150))
        val = tk.Label(row, text=str(view[key]), bg=CARD, fg=ACCENT_HI, width=4, font=fonts["bold"])

        def step_by(d):
            view[key] = max(lo, min(hi, view[key] + d * step))
            val.config(text=str(view[key]))
            save_view(view)
            if on_change:
                on_change(view[key])

        def arrow(sym, d):
            b = tk.Label(row, text=sym, bg=FAINT, fg=FG, width=2, font=fonts["bold"], cursor="hand2")
            b.pack(side="right", padx=1)
            b.bind("<Button-1>", lambda e: step_by(d))
            b.bind("<Enter>", lambda e: b.config(bg=ACCENT, fg=TOP))
            b.bind("<Leave>", lambda e: b.config(bg=FAINT, fg=FG))

        arrow("+", 1)                                    # packed right to left: - value +
        val.pack(side="right")
        arrow("−", -1)

    choosers = []

    def chooser(text, key, options, on_pick=None, translate=True):
        """A label, then a row of pills under it; the chosen one is highlighted."""
        row = row_frame()
        T(tk.Label(row, bg=CARD, fg=FG, font=fonts["norm"], anchor="w"), text).pack(fill="x")
        pills = tk.Frame(row, bg=CARD)
        pills.pack(fill="x", pady=(3, 0))
        opts = {}

        def paint():
            for name, b in opts.items():
                on = view[key] == name
                b.config(bg=ACCENT if on else FAINT, fg=TOP if on else SUBFG)

        def pick(name):
            view[key] = name
            save_view(view)
            (on_pick or (lambda n: apply_sizes()))(name)
            paint()
        for name, label in options:
            b = tk.Label(pills, font=fonts["small"], padx=6, pady=1, cursor="hand2")
            if translate:
                T(b, label)
            else:
                b.config(text=label)
            b.pack(side="left", padx=(0, 2))
            b.bind("<Button-1>", lambda e, n=name: pick(n))
            opts[name] = b
        paint()
        choosers.append(paint)

    def set_language(lang):
        view["lang"] = lang
        set_lang(lang)
        save_view(view)
        i18n[:] = [x for x in i18n if x[0].winfo_exists()]     # windows closed since (the effect picker)
        for w, text, upper in i18n:
            w.config(text=tr(text).upper() if upper else tr(text))
        for paint in choosers:
            paint()
        rot["ver"] = None                           # the rotation redraws in the new language
        apply_sizes()                                # back to the base width, refresh widens it if needed
        if tut["win"] is not None:
            render_tutorial()

    window_paints = []

    def window_row(glyph, text, is_open, toggle):
        """A window: its icon, its name and a switch that opens / closes it."""
        row = row_frame()
        if has_icons:
            tk.Label(row, text=glyph, bg=CARD, fg=SUBFG, font=fonts["icon"], width=2).pack(side="left",
                                                                                         padx=(0, 6))
        lab = T(tk.Label(row, bg=CARD, fg=FG, font=fonts["norm"], anchor="w", cursor="hand2"), text)
        lab.pack(side="left", fill="x", expand=True)
        sw = tk.Canvas(row, width=34, height=18, bg=CARD, highlightthickness=0, cursor="hand2")
        sw.pack(side="right")
        last = [None]

        def paint():                                     # each refresh: it also opens / closes elsewhere
            on = bool(is_open())
            if on != last[0]:
                last[0] = on
                paint_switch(sw, on)

        def flip(e=None):
            toggle()
            paint()
        for w in (row, lab, sw):
            w.bind("<Button-1>", flip)
        window_paints.append(paint)
        paint()

    PREVIEW = 0                                          # the breakdown opened before anyone is in a fight

    def toggle_breakdown():
        """Your breakdown (before a fight an empty one, to place it), or closed."""
        if state["detail"] is not None:
            state["detail"] = None
            return
        mine = next(iter(D().me), None)
        first = state["players"][0]["aid"] if state["players"] else None
        state["detail"] = mine if mine is not None else first if first is not None else PREVIEW

    def toggle_watch_bar():
        cfg_vars[(None, "watch_bar")].set(not view["watch_bar"])    # its switch in the Effects wrench
        changed()

    def toggle_score():
        view["gb_score"] = not view["gb_score"]
        save_view(view)

    cur["tab"] = wtab
    section("Windows")
    window_row("\uE9D2", "Breakdown", lambda: state["detail"] is not None, toggle_breakdown)
    window_row("\uE8B7", "Skill rotation", lambda: rot["open"], toggle_rot)
    window_row("\uE945", "Effects", lambda: eff["open"], toggle_eff)
    window_row("\uE916", "Watch bar", lambda: view["watch_bar"], toggle_watch_bar)
    window_row("\uE81C", "Fight history", lambda: hist["open"], toggle_hist)
    window_row("\uE734", "Guild boss score", lambda: view["gb_score"], toggle_score)
    whint = T(tk.Label(cur["card"], bg=CARD, fg=DIM, font=fonts["small"], anchor="w", justify="left"),
              "Open a window to place it before a fight. While this tab is open, the watch bar shows "
              "even when empty, so you can drag it into place.")
    whint.pack(fill="x", pady=(2, 4))
    wrapped.append((whint, 40))
    cur["tab"] = cfg
    section("Display")
    chooser("Language", "lang", [(l, LANG_NAMES[l]) for l in LANGS], on_pick=set_language, translate=False)
    chooser("Icons", "icon_size", [(n, n) for n in SIZE_NAMES])
    chooser("Text", "font_size", [(n, n) for n in SIZE_NAMES])
    check("Exact numbers (4,820,000 instead of 4.82M)", None, "exact")
    check("Details under the bars (DPS, crit, max hit, enemy HP)", None, "bar_details")
    check("Player names (instead of Player 2, Player 3, ...)", None, "player_names")
    op = row_frame()
    T(tk.Label(op, bg=CARD, fg=FG, font=fonts["norm"]), "Opacity").pack(side="left")
    op_val = tk.Label(op, text=f"{view['opacity']}%", bg=CARD, fg=ACCENT_HI, width=5, font=fonts["bold"])

    def set_opacity(v):
        view["opacity"] = int(float(v))
        op_val.config(text=f"{view['opacity']}%")
        root.attributes("-alpha", view["opacity"] / 100)
        dwin.attributes("-alpha", view["opacity"] / 100)
        rwin.attributes("-alpha", view["opacity"] / 100)
        hwin.attributes("-alpha", view["opacity"] / 100)
        ewin.attributes("-alpha", view["opacity"] / 100)
        wwin.attributes("-alpha", view["opacity"] / 100)
        swin.attributes("-alpha", view["opacity"] / 100)
        for ov in (win, dov, wov, sov):                       # their layered style and alpha again (100% too)
            ov.set_locked(state["locked"])
        save_view(view)
    op_val.pack(side="right")
    # the slider handle takes the Scale's background colour: amber on a grey track
    tk.Scale(op, from_=20, to=100, orient="horizontal", resolution=1, showvalue=False, command=set_opacity,
             bg=ACCENT, troughcolor=FAINT, activebackground=ACCENT_HI, highlightthickness=0, bd=0,
             sliderrelief="flat", sliderlength=16, width=10, length=140,
             variable=tk.IntVar(root, value=view["opacity"])).pack(side="right", padx=(0, 6))
    section("General")
    check("Show enemy HP", None, "enemy_hp")
    check("Boss mode: a boss kill ends the fight (saved to the history)", None, "boss_mode")
    stepper("Max enemy bars", "max_enemies", 1, 20)
    check("Show monsters in Damage taken", None, "show_all")
    check("Start locked (click-through)", None, "start_locked")
    stepper("Auto reset after N s idle (0 = off)", "auto_reset", 0, 3600, step=5,
            on_change=lambda v: setattr(meter, "auto_reset", v))
    rp = row_frame()
    rp_b = T(tk.Label(rp, bg=FAINT, fg=FG, font=fonts["norm"], padx=10, pady=3, cursor="hand2"),
             "Reset window positions")
    rp_b.pack(side="left", pady=(4, 2))

    def reset_positions():
        """Meter back to its first-start spot, the breakdown beside it; every window its own size."""
        view["sizes"] = {}
        apply_sizes()
        rot["rows"] = hist["size"] = eff["size"] = None
        root.geometry("+60+60")
        root.update_idletasks()
        dwin.geometry(f"+{60 + root.winfo_width() + 10}+60")
        dshown["placed"] = True
        save_positions()
        rp_b.config(text="\u2713 " + tr("Positions reset"), bg=GOOD, fg=TOP)
        root.after(1500, lambda: rp_b.config(text=tr("Reset window positions"), bg=FAINT, fg=FG))
    rp_b.bind("<Button-1>", lambda e: reset_positions())
    rp_b.bind("<Enter>", lambda e: rp_b.config(bg=ACCENT, fg=TOP) if rp_b.cget("bg") == FAINT else None)
    rp_b.bind("<Leave>", lambda e: rp_b.config(bg=FAINT, fg=FG) if rp_b.cget("bg") == ACCENT else None)

    net = {"rows": {}, "paint": None}
    if live is not None:
        # capture adapter: all of them (default), or one when a VPN etc. gets in the way
        section("Network adapter")
        net_list = tk.Frame(cur["card"], bg=CARD)
        net_list.pack(fill="x", pady=(3, 0))
        net_hint = tk.Label(cur["card"], bg=CARD, fg=DIM, font=fonts["small"], anchor="w", justify="left")
        net_hint.pack(fill="x", pady=(2, 0))
        wrapped.append((net_hint, 40))
        net_ref = T(tk.Label(cur["card"], bg=CARD, fg=ACCENT_HI, font=fonts["small"], anchor="w",
                             cursor="hand2"), "Refresh list")
        net_ref.pack(fill="x", pady=(2, 2))

        def net_paint():
            gip = live.game_ip()
            for key, (b, ip) in net["rows"].items():
                on = view["iface"] == key
                b.config(bg=ACCENT if on else FAINT, fg=TOP if on else SUBFG)
                b.config(text=("● " if gip and ip == gip else "   ") + b.base)
            names = [k for k, (b, ip) in net["rows"].items() if ip and ip == gip]
            net_hint.config(text=tr("Game traffic on: {name}", name=names[0]) if names
                            else tr("Waiting for game traffic"))

        def net_pick(key):
            view["iface"] = key
            save_view(view)
            live.start(key)
            net_paint()

        def net_build():
            for w in net_list.winfo_children():
                w.destroy()
            net["rows"] = {}
            items = [("all", None, tr("All adapters (automatic)"))]
            items += [(name, ip, f"{name[:26]}  {ip}") for name, ip in netif.adapters()]
            if not any(k == view["iface"] for k, _, _ in items):    # saved adapter is gone
                items.append((view["iface"], None, view["iface"] + "  (" + tr("not connected") + ")"))
            for key, ip, label in items:
                b = tk.Label(net_list, font=fonts["small"], padx=6, pady=2, anchor="w", cursor="hand2")
                b.base = label
                b.pack(fill="x", pady=1)
                b.bind("<Button-1>", lambda e, k=key: net_pick(k))
                net["rows"][key] = (b, ip)
            net_paint()
        def net_refresh():
            live.start(view["iface"])                    # picks up adapters connected since
            net_build()
            apply_sizes()
        net_ref.bind("<Button-1>", lambda e: net_refresh())
        net_build()
        net["paint"] = net_paint
        choosers.append(net_build)                       # re-labelled on a language change
    tk.Frame(cfg, bg=BG, height=6).pack()

    # dropdown menus: a window's wrench (its options) and the title bar's D / T picker. Built once,
    # hidden; one shows at a time, under its button, and that button again closes it
    menus = {"open": None}                               # (menu, its button) while one shows

    def menu_win():
        m = tk.Toplevel(root)
        m.overrideredirect(True)
        m.attributes("-topmost", True)
        m.attributes("-alpha", view["opacity"] / 100)
        m.configure(bg=BG, highlightthickness=1, highlightbackground=ACCENT)
        m.withdraw()
        return m

    def close_menu(head=None):
        """The menu showing (only if its button is in head, when given) hidden."""
        if menus["open"] is not None and (head is None or menus["open"][1].master is head):
            menus["open"][0].withdraw()
            menus["open"] = None

    def open_menu(m, b, on_open=None):
        same = menus["open"] is not None and menus["open"][0] is m
        close_menu()
        if same:
            return
        if on_open:
            on_open()
        m.update_idletasks()
        x = max(0, b.winfo_rootx() + b.winfo_width() - m.winfo_reqwidth())   # right edges lined up
        m.geometry(f"+{x}+{b.winfo_rooty() + b.winfo_height() + 4}")
        m.deiconify()
        if not hasattr(m, "ov"):                         # clickable, but never takes focus from the game
            m.ov = OverlayWindow(m)
            m.ov.set_locked(False)
        menus["open"] = (m, b)
        raise_all()

    def options_menu(build, w):
        """A wrench menu: the settings build() adds, in the same cards as the settings tab, in the
        fonts of window w."""
        old, ctx["win"] = ctx["win"], w
        m = menu_win()
        cur["tab"] = m
        build()
        tk.Frame(m, bg=BG, height=PAD).pack()
        ctx["win"] = old
        return m

    def wrench(head, m, w):
        old, ctx["win"] = ctx["win"], w
        b = btn("\uE90F", "Opt", lambda: open_menu(m, b), head)
        ctx["win"] = old
        return b

    def detail_options():
        section("Your details")
        check("Show each hero separately", "me", "heroes")
        check("Show each skill separately", "me", "skills")
        check("Open my details when a fight starts", None, "auto_detail")
        section("Teammate details")
        check("Show each hero separately", "others", "heroes")
        check("Show each skill separately", "others", "skills")
        stepper("Max detail rows", "max_rows", 5, 80)

    def rot_options():
        section("Skill rotation")
        check("Compact view (only the icons)", None, "rot_small")

    def eff_options():
        section("Effects")
        check("Show hidden effects", None, "fx_hidden")
        check("Show the watch bar (watched effects, a boss's ultimate countdown)", None, "watch_bar")
    detail_m = options_menu(detail_options, "detail")    # its wrench goes in after the breakdown's buttons
    wrench(rhead, options_menu(rot_options, "rot"), "rot")
    wrench(ehead, options_menu(eff_options, "fx"), "fx")

    def set_tab(tab):
        state["tab"] = tab
        for w in (cfg, wtab):
            w.pack_forget()
        if tab == "meter":
            canvas.pack(fill="both", expand=True, pady=(6, 2))
        else:
            canvas.pack_forget()
            (cfg if tab == "config" else wtab).pack(fill="both", expand=True)

    def save_positions():
        """Where both windows are, for the next start. The breakdown's only once it
        has been shown (until then it opens beside the meter)."""
        try:
            json.dump([root.winfo_x(), root.winfo_y()], open(POS_FILE, "w"))
            if dshown["placed"]:
                json.dump([dwin.winfo_x(), dwin.winfo_y()], open(DETAIL_POS_FILE, "w"))
        except OSError:
            pass

    def close():
        save_positions()
        with meter.lock:                                 # the fight going on goes to the history too
            meter.finish_fight()
        root.destroy()
    root.protocol("WM_DELETE_WINDOW", close)             # taskbar right-click > Close window

    def set_locked(locked):
        state["locked"] = locked
        win.set_locked(locked)
        dov.set_locked(locked)
        wov.set_locked(locked)                           # the watch bar: dragged while unlocked
        sov.set_locked(locked)                           # the score window too
        wwin.configure(highlightbackground=BG if locked else ACCENT)
        swin.configure(highlightbackground=BG if locked else ACCENT)
        root.configure(highlightbackground=BG if locked else ACCENT)
        dwin.configure(highlightbackground=BG if locked else ACCENT)
        show_grips()
        if locked:
            close_menu()
            set_tab("meter")
            save_positions()

    def toggle_config(tab="config"):
        if state["tab"] == tab:
            set_tab("meter")
            return
        if state["locked"]:                      # the config and windows tabs need clicks
            set_locked(False)
        set_tab(tab)

    def toggle_view(key):
        v = cfg_vars[(None, key)]
        v.set(not v.get())
        changed()

    def toggle_all():
        toggle_view("show_all")

    def toggle_detail(aid):
        """Open that player's details; opening one closes the other, same one closes."""
        state["detail"] = None if state["detail"] == aid else aid
        set_tab("meter")

    def nav(what):
        """The breakdown's < > buttons: the next / previous player, wrapping around."""
        players = [r["aid"] for r in state["players"]]
        if state["detail"] is None or not players:
            return
        i = players.index(state["detail"]) if state["detail"] in players else -1
        state["detail"] = players[(i + (1 if what == "next" else -1)) % len(players)]
        set_tab("meter")

    actions = {HOTKEY_LOCK: lambda: set_locked(not state["locked"])}

    btn("", "X", close)                         # close
    lock_b = btn("", "Lock", lambda: set_locked(True))          # lock
    reset_b = btn("", "R", reset)                                # reset
    help_b = btn("\uE897", "?", lambda: open_tutorial(0))               # tutorial
    cfg_b = btn("", "Cfg", toggle_config)              # settings
    win_b = btn("\uE7C4", "Win", lambda: toggle_config("windows"))   # every window: open / close
    # D / T: damage Done or Taken; a click opens the picker, each letter spelled out there
    mode_m = menu_win()
    mode_rows = {}
    for mode, letter, text in (("done", "D", "Damage done"), ("taken", "T", "Damage taken")):
        mrow = tk.Frame(mode_m, padx=8, pady=4, cursor="hand2")
        mrow.pack(fill="x")
        mkey = tk.Label(mrow, text=letter, font=fonts["bold"], width=2, cursor="hand2")
        mkey.pack(side="left", padx=(0, 8))
        mlab = T(tk.Label(mrow, font=fonts["norm"], anchor="w", cursor="hand2"), text)
        mlab.pack(side="left", fill="x", expand=True)
        for w in (mrow, mkey, mlab):
            w.bind("<Button-1>", lambda e, m=mode: (state.update(mode=m), close_menu()))
        mode_rows[mode] = (mrow, mkey, mlab)

    def paint_mode_menu():
        for mode, (mrow, mkey, mlab) in mode_rows.items():
            on = state["mode"] == mode
            mrow.config(bg=CARD if on else PANEL)
            mlab.config(bg=CARD if on else PANEL, fg=FG if on else SUBFG)
            mkey.config(bg=ACCENT if on else FAINT, fg=TOP if on else FG)
    mode_b = tk.Label(bar, text="D", bg=FAINT, fg=FG, padx=7, font=fonts["bold"], cursor="hand2")
    mode_b.pack(side="right", padx=(0, 6))
    mode_b.bind("<Button-1>", lambda e: open_menu(mode_m, mode_b, paint_mode_menu))
    mode_b.bind("<Enter>", lambda e: mode_b.config(bg=ACCENT, fg=TOP))
    mode_b.bind("<Leave>", lambda e: mode_b.config(bg=FAINT, fg=FG))
    ctx["win"] = "detail"
    btn("\uE8BB", "X", lambda: state.update(detail=None), dhead)    # breakdown: close, next, previous
    btn("\uE76C", ">", lambda: nav("next"), dhead)
    btn("\uE76B", "<", lambda: nav("prev"), dhead)

    def detail_who():
        """Whose settings the breakdown follows: "me" (you, or the tour's sample of you) or "others"."""
        return "me" if state["detail"] in D().me or state["detail"] in (PREVIEW, -1) else "others"

    def detail_glyph():
        small = not view[detail_who()]["skills"]
        if has_icons:
            return "\uE740" if small else "\uE73F"   # full screen / back to window
        return "+" if small else "-"

    def detail_size():
        """Minimized (each hero and their damage) <-> maximized (each of their skills too): the
        wrench's "Show each skill separately" for whoever is shown, so the two stay the same."""
        v = cfg_vars[(detail_who(), "skills")]
        v.set(not v.get())
        changed()
        dmin_b.config(text=detail_glyph())
    dmin_b = btn(detail_glyph(), detail_glyph(), detail_size, dhead)
    wrench(dhead, detail_m, "detail")
    rot_b = btn("\uE8B7", "Rot", lambda: toggle_rot(), dhead)       # your skill rotation (preview)
    rot_b.pack_forget()
    ctx["win"] = "main"

    def start_drag(e):
        state["drag"] = (e.x_root - root.winfo_x(), e.y_root - root.winfo_y())

    def do_drag(e):
        if state["drag"]:
            root.geometry(f"+{e.x_root - state['drag'][0]}+{e.y_root - state['drag'][1]}")

    for w in (bar, dot, title):
        w.bind("<Button-1>", start_drag)
        w.bind("<B1-Motion>", do_drag)
        w.bind("<ButtonRelease-1>", lambda e: save_positions())

    def click(e):
        y = canvas.canvasy(e.y)                       # scrolled, in a resized meter
        box = state.get("hist_box")
        if box and box[0] <= y < box[1]:              # the saved fight banner: back to live
            show_fight(None)
            return
        box = state.get("mon_box")
        if box and box[0] <= y < box[1]:              # the "Include monsters" switch
            toggle_all()
            return
        for y0, y1, aid in state["enemy_boxes"]:     # an enemy bar: damage to it only
            if y0 <= y < y1:
                state["target"] = None if state["target"] == aid else aid
                return
        for y0, y1, aid in state["hit_boxes"]:
            if y0 <= y < y1 and aid is not None:
                toggle_detail(aid)
                return

    canvas.bind("<Button-1>", click)
    canvas.bind("<Button-3>", lambda e: state.update(detail=None))

    need = {w: 0 for w in WINS}                  # px a window is short of, to show all text in full

    def fit(text, font, width, times=1):
        """Text is not cut while the window sizes itself: if it is wider than width, note how
        much wider the window being drawn must get (times: how many such columns share that
        width) and refresh widens it. A resized window keeps its width: the text ends in …"""
        over = font.measure(text) - width
        if over <= 0:
            return text
        if user_size(ctx["win"]):
            while text and font.measure(text + "…") > width:
                text = text[:-1]
            return text.rstrip() + "…" if text else ""
        need[ctx["win"]] = max(need[ctx["win"]], int(over * times) + 2)
        return text

    def rtext(x, y, parts, canvas=canvas):
        """Draw (text, font, colour) parts right-aligned at x, in reading order.
        Returns the x left of them."""
        for text, font, color in reversed(parts):
            if text:
                canvas.create_text(x, y, text=text, anchor="e", fill=color, font=font)
                x -= font.measure(text) + 6
        return x

    def card(x0, y, x1, h, frac, colors, bg=CARD, canvas=canvas):
        """A rounded card with a bar filling frac of it and a bright underline."""
        fill, edge = colors
        rrect(canvas, x0, y, x1, y + h, R, fill=bg)
        bw = int((x1 - x0) * max(0.0, min(1.0, frac)))
        if bw > 0:
            rrect(canvas, x0, y, x0 + bw, y + h, R, fill=fill)
        if bw > 2 * R:
            rrect(canvas, x0 + 3, y + h - 4, x0 + bw - 3, y + h - 2, 1, fill=edge)

    def bar_h():
        """A player's (and an enemy's) bar in the main window: two lines, or one without the
        details under it (bar_details off)."""
        return L["ROWH"][0] if view["bar_details"] else L["lb"] + 10

    def draw_row(r, y, top, rank=None):
        W, lv, v = L["W"], r["level"], r["value"]
        h = bar_h() if lv == 0 else L["ROWH"][lv]
        sub = r.get("sub") if view["bar_details"] or lv else None
        x0, x1 = PAD + L["INDENT"][lv], W - PAD
        pct = 100 * v / max(1, r["parent"])
        frac = v / top if lv == 0 else v / max(1, r["parent"])      # sub rows: share of parent
        card(x0, y, x1, h, frac, BARS[lv][1 if r["me"] else 0])
        if lv == 0 and r["aid"] == state["detail"]:
            rrect(canvas, x0, y, x1, y + h, R, fill="", outline=ACCENT_HI, width=1.5)
        cy = y + (h - 2) // 2
        tx = x0 + 8
        img = image(r["icon"]) if r.get("icon") else None
        if img is not None:
            canvas.create_image(x0 + 4, cy, image=img, anchor="w")
            tx = x0 + 4 + img.width() + 6
            img2 = image(r["icon2"]) if r.get("icon2") else None
            if img2 is not None:                  # combo: both heroes' ultimate icons
                canvas.create_image(tx - 3, cy, image=img2, anchor="w")
                tx += img2.width() + 3
        if lv == 2:
            parts = []
            if r.get("over"):                     # the kill took more than the HP left
                parts.append((tr("overkill {n}", n=fmt(r["over"])), fonts["small"], "#ff8a80"))
            parts += [(f"{r['hits']}×", fonts["small"], DIM), (fmt(v), fonts["small"], FG),
                      (f"{pct:.0f}%", fonts["small"], SUBFG)]
            left = rtext(x1 - 8, cy, parts)
            if img is not None and r.get("tag"):  # icon shared with another row: say which
                canvas.create_text(tx, cy, text=r["tag"], anchor="w", fill=ACCENT_HI, font=fonts["small"])
            if img is None:                       # no icon for this skill: name it instead
                canvas.create_text(tx, cy, text=fit(r["label"], fonts["small"], left - tx), anchor="w",
                                   fill=FG, font=fonts["small"])
            return
        ty = y + (h - 2 - L["lb"] - (L["ls"] if sub is not None else 0)) // 2 + L["lb"] // 2   # name; sub below
        if rank:                                  # rank badge: gold / silver / bronze for the top 3
            d = L["lb"] - 2
            medal = MEDALS.get(rank)
            canvas.create_oval(tx, ty - d // 2, tx + d, ty + d // 2, fill=medal or FAINT, width=0)
            canvas.create_text(tx + d // 2, ty, text=str(rank), fill=TOP if medal else FG, font=fonts["badge"])
            tx += d + 7
        left = rtext(x1 - 8, ty, [(fmt(v), fonts["bold"], FG), (f"{pct:.0f}%", fonts["small"], SUBFG)])
        name_col = ACCENT_HI if r["me"] and lv == 0 else FG
        canvas.create_text(tx, ty, text=fit(r["label"], fonts["bold"], left - tx - 4),
                           anchor="w", fill=name_col, font=fonts["bold"] if lv == 0 else fonts["norm"])
        if sub is not None:
            canvas.create_text(tx, ty + L["lb"] // 2 + L["ls"] // 2 + 1, text=fit(sub, fonts["small"], x1 - 8 - tx),
                               anchor="w", fill=SUBFG, font=fonts["small"])

    def draw_enemies(enemies, y):
        """Red HP cards, shrinking with the HP left. The enemy the damage is
        filtered to is outlined. Returns the y below them."""
        W, h = L["W"], (L["lb"] + L["ls"] + 14 if view["bar_details"] else bar_h())
        x0, x1 = PAD, L["W"] - PAD
        boxes = []
        for e in enemies:
            ty1, ty2 = y + 5 + L["lb"] // 2, y + 6 + L["lb"] + L["ls"] // 2
            if not view["bar_details"]:                # one line: name and HP %
                ty1 = y + (h - 2) // 2
            if e["frozen"]:
                frac, big, small = 0, "", tr("HP not reported")
            else:
                frac = 0 if e["dead"] else e["hp"] / e["max"]
                big = tr("defeated") if e["dead"] else f"{100 * frac:.0f}%"
                small = f"{fmt(e['hp'])} / {fmt(e['max'])}"
            card(x0, y, x1, h, frac, (ENEMY_FILL, ENEMY_EDGE), bg=ENEMY_BG)
            if e["over"]:
                small += "   " + tr("overkill {n}", n=fmt(e["over"]))
            if e.get("level"):                        # a boss that levels up when killed
                small += "   " + tr("Lv {n}/{m}", n=e["level"][0], m=e["level"][1])
            if e.get("resets"):
                small += "   " + tr("{n} kills", n=e["resets"])
            col = DIM if e["dead"] else FG
            canvas.create_text(x1 - 8, ty1, text=big, anchor="e", fill=col, font=fonts["bold"])
            name = fit(e["label"], fonts["bold"], x1 - x0 - 24 - fonts["bold"].measure(big))
            canvas.create_text(x0 + 8, ty1, text=name, anchor="w", fill=col, font=fonts["bold"])
            if view["bar_details"]:
                canvas.create_text(x0 + 8, ty2, text=fit(small, fonts["small"], x1 - x0 - 16), anchor="w",
                                   fill="#e8c4c0" if not e["dead"] else DIM, font=fonts["small"])
            if e["aid"] == state["target"]:           # the damage shown is to this one
                rrect(canvas, x0 + 1, y + 1, x1 - 1, y + h - 1, R, fill="", outline=TARGET, width=2)
            boxes.append((y, y + h, e["aid"]))
            y += h + GAP
        state["enemy_boxes"] = boxes
        if enemies:
            canvas.create_line(PAD + 4, y + 3, W - PAD - 4, y + 3, fill=FAINT)
            y += 9
        return y

    def draw_top(y):
        """Above the enemies: the saved fight on screen (a click goes back to live). Only
        the enemy bars follow (the guild boss score has its own window). Returns the y below."""
        x0, x1 = PAD, L["W"] - PAD
        h = L["lb"] + L["ls"] + 14
        state["hist_box"] = None

        def chip(x, cy, text, color):
            cw = fonts["badge"].measure(text) + 10
            rrect(canvas, x, cy - L["ls"] // 2 + 1, x + cw, cy + L["ls"] // 2 - 1, 4, fill=color)
            canvas.create_text(x + cw // 2, cy, text=text, fill=TOP, font=fonts["badge"])
            return x + cw + 6
        if state["hist"] is not None:
            d = state["hist"].loaded
            ty1, ty2 = y + 5 + L["lb"] // 2, y + 6 + L["lb"] + L["ls"] // 2
            rrect(canvas, x0, y, x1, y + h, R, fill="#16283f")
            x = chip(x0 + 8, ty1, tr("HISTORY"), "#5b9cff")
            canvas.create_text(x, ty1, text=fit(d.get("name") or tr("Fight"), fonts["bold"], x1 - x - 8),
                               anchor="w", fill=FG, font=fonts["bold"])
            canvas.create_text(x0 + 8, ty2, anchor="w", fill=SUBFG, font=fonts["small"],
                               text=fit(f"{d.get('saved') or ''}  ·  " + tr("click here: back to live"),
                                        fonts["small"], x1 - x0 - 16))
            state["hist_box"] = (y, y + h)
            y += h + GAP
        return y

    def draw(players, enemies):
        W, ROWH = L["W"], L["ROWH"]
        canvas.delete("all")
        boxes, y = [], draw_enemies(enemies, draw_top(0))
        state["mon_box"] = None
        if state["mode"] == "taken":                  # monsters only matter for damage taken
            h, on = L["ls"] + 12, view["show_all"]
            rrect(canvas, PAD, y, W - PAD, y + h, R, fill=PANEL)
            canvas.create_text(PAD + 10, y + h / 2, text=tr("Include monsters"), anchor="w", fill=SUBFG,
                               font=fonts["small"])
            sx, sh = W - PAD - 40, 16
            sy = y + (h - sh) / 2
            rrect(canvas, sx, sy, sx + 30, sy + sh, 8, fill=ACCENT if on else FAINT)
            kx = sx + (22 if on else 8)
            canvas.create_oval(kx - 6, sy + 2, kx + 6, sy + sh - 2, fill=TOP if on else SUBFG, width=0)
            state["mon_box"] = (y, y + h)
            y += h + GAP + 2
        top = max((r["value"] for r in players), default=1) or 1
        for i, r in enumerate(players):
            draw_row(r, y, top, rank=i + 1)
            boxes.append((y, y + bar_h() + GAP, r["aid"]))
            y += bar_h() + GAP
        if not players:
            h = ROWH[0] + 8
            rrect(canvas, PAD, y, W - PAD, y + h, R, fill=PANEL)
            canvas.create_text(W // 2, y + h // 2 - L["ls"] // 2, fill=SUBFG, font=fonts["norm"],
                               text=tr("Waiting for combat"))
            canvas.create_text(W // 2, y + h // 2 + L["lb"] // 2, fill=DIM, font=fonts["small"],
                               text=tr("no damage yet" if state["mode"] == "done" else "no damage taken yet"))
            y += h + GAP
        state["hit_boxes"] = boxes
        return y

    @in_win("detail")
    def draw_detail(player, idx, n, label, rows, summary):
        """The breakdown window: a header with the player, four stat tiles, then
        each hero (portrait, share of the player's damage) with its skills under it."""
        W, c = L["DW"], dcan
        c.delete("all")
        me = bool(player and player["me"])
        dname.config(text=label, fg=ACCENT_HI if me else FG)
        target = D().enemy_label(state["target"]) if state["target"] is not None else None
        sub = tr("#{i} of {n}", i=idx + 1, n=n) if idx is not None else \
            tr("Waiting for combat") if state["detail"] == PREVIEW else tr("not in the list")
        if player and state["mode"] == "done":
            sub += "  ·  " + tr("{p}% of party damage", p=f"{100 * player['value'] / max(1, player['parent']):.0f}")
        if target:
            sub += "  ·  " + tr("to {t}", t=target)
        drank.config(text=fit(sub, fonts["small"], W - 150))
        hero = next((r for r in rows if "hits" not in r), None)
        img = image(hero["icon"]) if hero and hero.get("icon") else None
        if img is None:
            dportrait.pack_forget()
        else:
            dportrait.config(image=img)
            if not dportrait.winfo_ismapped():
                dportrait.pack(side="left", padx=(0, 8), before=dtitle)

        y = draw_tabs(c, W)
        if state["dtab"] == "graph":              # the graph instead of the damage rows
            return draw_graph(c, W, y, state["detail"])

        # stat tiles
        tg = 4
        tw = (W - 2 * PAD - 3 * tg) / 4
        tiles = ((tr("DAMAGE"), fmt(summary["done"])), (tr("DPS"), fmt(summary["dps"])),
                 (tr("CRIT"), f"{summary['crit']:.0f}%"), (tr("MAX HIT"), fmt(summary["max_hit"])))
        for i, (name, val) in enumerate(tiles):
            tx = PAD + i * (tw + tg)
            rrect(c, tx, y, tx + tw, y + L["TILEH"], R, fill=CARD)
            c.create_text(tx + 8, y + 6, text=name, anchor="nw", fill=DIM, font=fonts["section"])
            c.create_text(tx + 8, y + L["TILEH"] - 6, text=fit(val, fonts["bold"], tw - 12, times=4), anchor="sw",
                          fill=ACCENT_HI if (me and i == 0) else FG, font=fonts["bold"])
        y += L["TILEH"] + 10

        colors = BARS[0][1 if me else 0]
        for r in rows:
            if "hits" not in r:                   # a hero: card with portrait and share bar
                h, x0, x1 = L["HEROH"], PAD, W - PAD
                card(x0, y, x1, h, r["value"] / max(1, r["parent"]), colors, canvas=c)
                cy, tx = y + (h - 2) // 2, x0 + 8
                im = image(r["icon"]) if r.get("icon") else None
                if im is not None:
                    c.create_image(x0 + 5, cy, image=im, anchor="w")
                    tx = x0 + 5 + im.width() + 8
                left = rtext(x1 - 8, cy - L["ls"] // 2,
                             [(fmt(r["value"]), fonts["bold"], FG),
                              (f"{100 * r['value'] / max(1, r['parent']):.0f}%", fonts["small"], SUBFG)], canvas=c)
                c.create_text(tx, cy - L["ls"] // 2, text=fit(r["label"], fonts["bold"], left - tx), anchor="w",
                              fill=FG, font=fonts["bold"])
                c.create_text(tx, cy + L["lb"] // 2, text=fit(r["sub"], fonts["small"], x1 - 8 - tx), anchor="w",
                              fill=SUBFG, font=fonts["small"])
                y += h + GAP
                continue
            # a skill: icon, name and hits on the left, damage on the right, share as a thin bar
            h = L["SKH"]
            x0, x1 = PAD + (14 if r["level"] == 2 else 0), W - PAD
            rrect(c, x0, y, x1, y + h, R, fill=PANEL)
            cy, tx = y + (h - 4) // 2, x0 + 8
            im = image(r["icon"]) if r.get("icon") else None
            if im is not None:
                c.create_image(x0 + 5, cy, image=im, anchor="w")
                tx = x0 + 5 + im.width() + 8
                im2 = image(r["icon2"]) if r.get("icon2") else None
                if im2 is not None:               # combo: both heroes' ultimate icons
                    c.create_image(tx - 4, cy, image=im2, anchor="w")
                    tx += im2.width() + 4
            frac = r["value"] / max(1, r["parent"])
            ly, sy = cy - L["ls"] // 2, cy + L["lb"] // 2
            left = rtext(x1 - 8, ly, [(fmt(r["value"]), fonts["bold"], FG),
                                      (f"{100 * frac:.0f}%", fonts["small"], SUBFG)], canvas=c)
            nx = tx
            if r.get("tag"):                      # combo chip before the name
                tag = tr(r["tag"].capitalize()).upper()
                cw = fonts["badge"].measure(tag) + 10
                rrect(c, nx, ly - L["ls"] // 2 + 1, nx + cw, ly + L["ls"] // 2 - 1, 4, fill=ACCENT)
                c.create_text(nx + cw // 2, ly, text=tag, fill=TOP, font=fonts["badge"])
                nx += cw + 6
            c.create_text(nx, ly, text=fit(r["label"], fonts["norm"], left - nx - 4), anchor="w", fill=FG,
                          font=fonts["norm"])
            hits = r["hits"]
            parts = [(tr("{n} hits" if hits != 1 else "{n} hit", n=hits) + "  ·  "
                      + tr("avg {v}", v=fmt(r["value"] // max(1, hits))), fonts["small"], SUBFG)]
            if r.get("over"):
                parts.append(("  ·  " + tr("overkill {n}", n=fmt(r["over"])), fonts["small"], "#ff8a80"))
            sx = tx
            for text, font, color in parts:
                c.create_text(sx, sy, text=text, anchor="w", fill=color, font=font)
                sx += font.measure(text)
            bx0, bx1 = x0 + 6, x1 - 6                     # share of the hero's damage
            c.create_line(bx0, y + h - 3, bx1, y + h - 3, fill=FAINT, width=2)
            c.create_line(bx0, y + h - 3, bx0 + max(2, int((bx1 - bx0) * frac)), y + h - 3,
                          fill=colors[1], width=2)
            y += h + GAP
        if not rows:
            rrect(c, PAD, y, W - PAD, y + L["SKH"], R, fill=PANEL)
            c.create_text(W // 2, y + L["SKH"] // 2, text=tr("No damage yet (or details are off in settings)"),
                          fill=DIM, font=fonts["small"])
            y += L["SKH"] + GAP
        return y

    DTABS = (("damage", "Damage"), ("graph", "Graph"))

    def draw_tabs(c, W):
        """Damage | Graph at the top of the breakdown."""
        h, x, boxes = L["ls"] + 8, PAD, []
        for key, text in DTABS:
            t = tr(text)
            w = fonts["small"].measure(t) + 18
            on = state["dtab"] == key
            rrect(c, x, 0, x + w, h, h // 2, fill=ACCENT if on else CARD)
            c.create_text(x + w // 2, h // 2, text=t, fill=TOP if on else SUBFG, font=fonts["small"])
            boxes.append((x, x + w, key))
            x += w + 4
        state["dtab_boxes"] = (h, boxes)
        return h + 8

    def dclick(e):
        h, boxes = state.get("dtab_boxes", (0, []))
        if dcan.canvasy(e.y) < h:
            for x0, x1, key in boxes:
                if x0 <= e.x < x1:
                    state["dtab"] = key
    dcan.bind("<Button-1>", dclick)

    GRAPH_COLORS = ("#5b9cff", "#4cc38a", "#c77dff", "#ff7b72", "#56d4dd", "#f2c94c", "#ff9ecd", "#9aa5b8")
    GRAPH_SMOOTH = 5                             # s: DPS averaged over up to this many seconds

    def draw_graph(c, W, y, aid):
        """Damage over time: each player's DPS (a GRAPH_SMOOTH s average) across the fight,
        the player of this panel drawn thick, and the enemy's (or boss's) HP dashed."""
        g = D().graph(state["target"] if state["mode"] == "done" else None)
        if not g or not g[2]:
            rrect(c, PAD, y, W - PAD, y + L["SKH"], R, fill=PANEL)
            c.create_text(W // 2, y + L["SKH"] // 2, text=tr("No damage over time yet"), fill=DIM,
                          font=fonts["small"])
            return y + L["SKH"] + GAP
        t0, t1, series, hp = g
        n = int(t1 - t0) + 1
        smooth = max(1, min(GRAPH_SMOOTH, n // 12))  # short fights: less smoothing
        lines = []
        for i, (sid, lab, me, bins) in enumerate(sorted(series, key=lambda x: str(x[1]))):
            per = [bins.get(int(t0) + k, 0) for k in range(n)]
            sm, run = [], 0
            for k in range(n):                       # running average over `smooth` s
                run += per[k] - (per[k - smooth] if k >= smooth else 0)
                sm.append(run / min(k + 1, smooth))
            color = ACCENT if me else GRAPH_COLORS[i % len(GRAPH_COLORS)]
            lines.append((sid, lab, color, sm, sum(per)))
        top = max(max(ln[3]) for ln in lines) or 1
        gh = max(150, 10 * L["ls"])
        lx = fonts["badge"].measure(fmt(top)) + 10
        x0, x1 = PAD + 6 + lx, W - PAD - 10
        gy0, gy1 = y + 10, y + 10 + gh
        rrect(c, PAD, y, W - PAD, gy1 + L["ls"] + 10, R, fill=PANEL)
        for k in (0, 0.5, 1):                        # grid: 0, half, top DPS
            yy = gy1 - (gy1 - gy0) * k
            c.create_line(x0, yy, x1, yy, fill=FAINT, dash=(2, 3) if k else None)
            c.create_text(x0 - 5, yy, text=fmt(top * k), anchor="e", fill=DIM, font=fonts["badge"])
        span = max(1, n - 1)
        for k in (0, 0.5, 1):                        # time: start, middle, end
            secs = int(span * k)
            c.create_text(x0 + (x1 - x0) * k, gy1 + 4, text=f"{secs // 60}:{secs % 60:02d}", fill=DIM,
                          font=fonts["badge"], anchor="n" if 0 < k < 1 else ("nw" if k == 0 else "ne"))

        def px(k):
            return x0 + (x1 - x0) * k / span
        if len(hp) > 1:                              # enemy HP, 0..100% on the same height
            pts = []
            for t, f in hp:
                k = min(span, max(0, t - t0))
                pts += [px(k), gy1 - (gy1 - gy0) * f]
            c.create_line(*pts, fill=ENEMY_EDGE, width=1, dash=(4, 3))
            c.create_text(x1, gy0 - 2, text=tr("HP"), anchor="se", fill=ENEMY_EDGE, font=fonts["badge"])
        for sid, lab, color, sm, total in sorted(lines, key=lambda ln: ln[0] == aid):    # this player last
            if n < 2:
                continue
            pts = []
            for k, v in enumerate(sm):
                pts += [px(k), gy1 - (gy1 - gy0) * v / top]
            c.create_line(*pts, fill=color, width=3 if sid == aid else 1.5)
        y = gy1 + L["ls"] + 16
        x = PAD + 4                                  # legend: colour, player, average DPS
        for sid, lab, color, sm, total in lines:
            t = f"{lab}  {fmt(total / max(1.0, t1 - t0))}/s"
            w = fonts["small"].measure(t) + 22
            if x + w > W - PAD and x > PAD + 4:
                x, y = PAD + 4, y + L["ls"] + 6
            c.create_rectangle(x, y + L["ls"] // 2 - 2, x + 10, y + L["ls"] // 2 + 2, fill=color, width=0)
            c.create_text(x + 14, y + L["ls"] // 2, text=t, anchor="w", fill=FG if sid == aid else SUBFG,
                          font=fonts["bold"] if sid == aid else fonts["small"])
            x += w
        return y + L["ls"] + 8

    # ---- tutorial: a card beside the meter; first start greets and offers it
    tut = {"win": None, "step": None}            # step None = the greeting
    # what each step opens, and what it outlines (see tutorial_rects)
    STEPS = ({"hl": ("meter",)},
             {"hl": ("rows",)},
             {"mode": "taken", "hl": ("seg", "mon")},
             {"hl": ("enemies",)},
             {"detail": True, "hl": ("detail", "row1")},
             {"detail": True, "dtab": "graph", "hl": ("detail",)},
             {"hl": ("enemies",)},
             {"rot": True, "hl": ("rotwin",)},
             {"fx": True, "hl": ("fxwin",)},
             {"fx": True, "hl": ("pick", "watch")},
             {"hist": True, "hl": ("histwin",)},
             {"unlock": True, "hl": ("lock", "banner")},
             {"hl": ("bar",)},
             {"tab": "windows", "hl": ("winb", "gear", "wtab")},
             {"hl": ("help", "reset")})
    HL_KEY = "#ff00fe"                           # transparent colour of the highlight layer

    def demo_players(mode):
        """Sample rows for the tour when there is no fight to show."""
        vals = ((4_820_000, 3_910_000, 1_250_000, 640_000) if mode == "done"
                else (1_200_000, 2_300_000, 800_000, 450_000))
        rows = [(v, -1 - i) for i, v in enumerate(vals)]
        rows.sort(key=lambda r: -r[0])
        tot = sum(vals)
        return [dict(level=0, label=tr("Me") if aid == -1 else tr("Player {n}", n=-aid), value=v, parent=tot,
                     me=aid == -1, aid=aid,
                     sub=(f"{v / 83:,.0f}/s  {tr('crit')} 41%  {tr('max')} {v // 9:,}" if mode == "done"
                          else f"{v / 83:,.0f}/s")) for v, aid in rows]

    def demo_enemies():
        return [dict(aid=-99, label=tr("Enemy {n}", n=1), hp=2_400_000, max=6_000_000, dead=False,
                     frozen=False, over=0),
                dict(aid=-98, label=tr("Enemy {n}", n=2), hp=0, max=3_000_000, dead=True, frozen=False,
                     over=55_000)]

    def demo_details(aid, players):
        p = next((r for r in players if r["aid"] == aid), players[0])
        v, me = p["value"], aid == -1
        a, b = int(v * 0.62), v - int(v * 0.62)
        rows = [dict(level=1, label="Ban", value=a, parent=v, sub=f"{a / 83:,.0f}/s", icon=hero_icon("ban")),
                dict(level=2, label=tr("Ultimate"), value=int(a * 0.6), parent=a, hits=3, over=120_000,
                     icon=_icon("ban_sword2h_special")),
                dict(level=2, label=tr("Normal attack"), value=a - int(a * 0.6), parent=a, hits=48, over=0,
                     icon=_icon("ban_sword2h_normal")),
                dict(level=1, label="Calla", value=b, parent=v, sub=f"{b / 83:,.0f}/s", icon=hero_icon("calla")),
                dict(level=2, label=tr("Special"), value=b, parent=b, hits=12, over=0,
                     icon=_icon("calla_gauntlets_special"))]
        for r in rows:
            r.update(me=me, aid=aid)
        return p["label"], rows, dict(done=v, dps=v / 83, crit=41, max_hit=v // 9)

    def tour_on():
        return tut["win"] is not None

    def apply_step(step):
        """Put the windows in the state a step talks about."""
        spec = STEPS[step] if step is not None else {}
        state["mode"] = spec.get("mode", "done")
        state["target"] = None
        set_tab(spec.get("tab", "meter"))
        state["detail"] = None
        tut["want_detail"] = bool(spec.get("detail"))
        state["dtab"] = spec.get("dtab", "damage")
        toggle_rot(bool(spec.get("rot")))                # the window a step talks about, open
        toggle_eff(bool(spec.get("fx")))
        toggle_hist(bool(spec.get("hist")))
        if spec.get("unlock") and state["locked"]:
            set_locked(False)

    def finish_tutorial():
        if tut["win"] is not None:
            tut["win"].destroy()
            tut["hl"].destroy()
            sv = tut["saved"]                    # windows back the way they were before the tour
            state.update(mode=sv["mode"], target=None, detail=None, dtab="damage")
            toggle_rot(False)
            toggle_eff(False)
            toggle_hist(False)
            set_tab("meter")
            if sv["locked"] != state["locked"]:
                set_locked(sv["locked"])
        tut["win"] = None
        view["tutorial_seen"] = True
        save_view(view)

    def tutorial_rects():
        """Screen rectangles to outline for the current step."""
        step = tut["step"]
        if step is None:
            return []

        def wrect(w, pad=3):
            if not w.winfo_ismapped():
                return None
            x, y = w.winfo_rootx(), w.winfo_rooty()
            return (x - pad, y - pad, x + w.winfo_width() + pad, y + w.winfo_height() + pad)

        def crect(c, y0, y1, pad=3):
            x, y = c.winfo_rootx(), c.winfo_rooty() - int(c.canvasy(0))
            return (x + PAD - pad, y + y0 - pad, x + c.winfo_width() - PAD + pad, y + y1 + pad)
        out = []
        boxes = state["hit_boxes"]
        for what in STEPS[step]["hl"]:
            r = None
            if what == "meter":
                r = wrect(root, 6)
            elif what == "rows" and boxes:
                r = crect(canvas, boxes[0][0], boxes[-1][1] - GAP)
            elif what == "row1" and boxes:
                r = crect(canvas, boxes[0][0], boxes[0][1] - GAP)
            elif what == "enemies" and state["enemy_boxes"]:
                r = crect(canvas, state["enemy_boxes"][0][0], state["enemy_boxes"][-1][1])
            elif what == "mon" and state.get("mon_box"):
                r = crect(canvas, *state["mon_box"])
            elif what == "banner" and state.get("banner_box"):
                gx, gy = guide.winfo_rootx(), guide.winfo_rooty()
                b0, b1 = state["banner_box"]
                r = (gx - 3, gy + b0 - 3, gx + guide.winfo_width() + 3, gy + b1 + 3)
            else:
                w = {"seg": mode_b, "detail": dwin if dshown["v"] else None, "lock": lock_b, "bar": bar,
                     "guide": guide, "cfg": cfg, "gear": cfg_b, "winb": win_b, "wtab": wtab, "help": help_b, "reset": reset_b,
                     "rotwin": rwin if rot["open"] else None, "fxwin": ewin if eff["open"] else None,
                     "pick": pick_b, "watch": wwin if watch["shown"] else None,
                     "histwin": hwin if hist["open"] else None}.get(what)
                r = wrect(w, 6 if what == "detail" else 3) if w is not None else None
            if r:
                out.append(r)
        return out

    def update_tutorial():
        """Each refresh while the tour is open: the card beside the windows (until it is
        dragged), the outlines around what the step explains, stacking card > outlines > meter."""
        tw, hw = tut["win"], tut["hl"]
        if tut.get("want_detail") and state["detail"] is None and state["players"]:
            state["detail"] = state["players"][0]["aid"]
        root.update_idletasks()
        wins = [root] + ([dwin] if dshown["v"] else [])
        left = min(w.winfo_x() for w in wins)
        right = max(w.winfo_x() + w.winfo_width() for w in wins)
        if not tut.get("moved"):
            cw, sw = tw.winfo_width(), root.winfo_screenwidth()
            x = right + 16 if right + 16 + cw <= sw else (left - cw - 16 if left - cw - 16 >= 0 else sw - cw - 10)
            tut["ov"].move(x, root.winfo_y())
        rects = tutorial_rects()
        c = tut["hlc"]
        c.delete("all")
        if not rects:
            tut["hlov"].show(False)
        else:
            m = 6
            x0, y0 = min(r[0] for r in rects) - m, min(r[1] for r in rects) - m
            x1, y1 = max(r[2] for r in rects) + m, max(r[3] for r in rects) + m
            c.config(width=x1 - x0, height=y1 - y0)
            tut["hlov"].place(x0, y0, x1 - x0, y1 - y0)
            pulse = (state["tick"] // 2) % 2              # gentle blink, every half second
            for rx0, ry0, rx1, ry1 in rects:
                rrect(c, rx0 - x0, ry0 - y0, rx1 - x0, ry1 - y0, R + 2, fill="",
                      outline=ACCENT_HI if pulse else ACCENT, width=3)
            tut["hlov"].show(True)
            tut["hlov"].place(x0, y0, x1 - x0, y1 - y0)
        tut["ov"].keep_on_top()

    def open_tutorial(step):
        tut["step"] = step
        if step is not None and not view["tutorial_seen"]:   # chose the tour: don't greet again
            view["tutorial_seen"] = True
            save_view(view)
        if tut["win"] is None:
            tut["saved"] = dict(mode=state["mode"], locked=state["locked"])
            tut["moved"] = False
            hw = tk.Toplevel(root)                           # outlines: transparent, click-through
            hw.overrideredirect(True)
            hw.attributes("-topmost", True)
            hw.configure(bg=HL_KEY)
            hw.attributes("-transparentcolor", HL_KEY)
            tut["hlc"] = tk.Canvas(hw, bg=HL_KEY, highlightthickness=0, width=1, height=1)
            tut["hlc"].pack()
            hw.geometry("1x1+0+0")
            tut["hlov"] = OverlayWindow(hw)
            tut["hlov"].set_locked(True)
            tut["hlov"].show(False)
            tut["hl"] = hw
            tw = tk.Toplevel(root)
            tw.overrideredirect(True)
            tw.attributes("-topmost", True)
            tw.configure(bg=PANEL, highlightthickness=1, highlightbackground=ACCENT)
            root.update_idletasks()
            x = root.winfo_x() + root.winfo_width() + 16
            if x + 440 > root.winfo_screenwidth():          # no room on the right: left of the meter
                x = max(0, root.winfo_x() - 456)
            tw.geometry(f"+{x}+{root.winfo_y()}")
            tut["ov"] = OverlayWindow(tw)
            tut["ov"].set_locked(False)                      # always clickable, never takes focus
            tut["win"] = tw
        apply_step(step)
        render_tutorial()

    def tbutton(parent, text, cmd, primary=False):
        bg, fg = (ACCENT, TOP) if primary else (FAINT, FG)
        b = tk.Label(parent, text=text, bg=bg, fg=fg, font=fonts["bold"] if primary else fonts["norm"],
                     padx=12, pady=4, cursor="hand2")
        b.bind("<Button-1>", lambda e: cmd())
        b.bind("<Enter>", lambda e: b.config(bg=ACCENT_HI if primary else DIM))
        b.bind("<Leave>", lambda e: b.config(bg=bg))
        return b

    @in_win("fixed")
    def render_tutorial():
        tw, step = tut["win"], tut["step"]
        for w in tw.winfo_children():
            w.destroy()
        width = max(360, 28 * fs_now())
        n = len(TUTORIAL)
        head = tk.Frame(tw, bg=TOP, padx=12, pady=6)
        head.pack(fill="x")
        tk.Label(head, text="SDS Meter" if step is None else tr("Step {i} of {n}", i=step + 1, n=n),
                 bg=TOP, fg=DIM, font=fonts["small"]).pack(side="left")
        x_b = tk.Label(head, text="\uE8BB" if has_icons else "X", bg=TOP, fg=DIM, cursor="hand2",
                       font=fonts["icon"] if has_icons else fonts["norm"])
        x_b.pack(side="right")
        x_b.bind("<Button-1>", lambda e: finish_tutorial())

        def tstart(e):
            tut["drag"] = (e.x_root - tw.winfo_x(), e.y_root - tw.winfo_y())

        def tdrag(e):
            tut["moved"] = True
            tw.geometry(f"+{e.x_root - tut['drag'][0]}+{e.y_root - tut['drag'][1]}")
        for w in (head,) + tuple(head.winfo_children()[:1]):
            w.bind("<Button-1>", tstart)
            w.bind("<B1-Motion>", tdrag)

        body = tk.Frame(tw, bg=PANEL, padx=18, pady=14)
        body.pack(fill="x")
        if step is None:
            title, text = tr("Hi! Welcome to SDS Meter"), tr(
                "It shows your party's damage live while you play. Want a quick tour of everything it can do?")
        else:
            title, text = tutorial_step(step)
        tk.Label(body, text=title, bg=PANEL, fg=ACCENT_HI, font=fonts["title"], anchor="w", justify="left",
                 wraplength=width - 36).pack(fill="x")
        tk.Label(body, text=text, bg=PANEL, fg=FG, font=fonts["norm"], anchor="w", justify="left",
                 wraplength=width - 36).pack(fill="x", pady=(8, 0))
        if step is None:                                     # pick a language before the tour
            tk.Label(body, text=tr("Language"), bg=PANEL, fg=DIM, font=fonts["small"],
                     anchor="w").pack(fill="x", pady=(12, 3))
            pills = tk.Frame(body, bg=PANEL)
            pills.pack(fill="x")
            for l in LANGS:
                on = view["lang"] == l
                b = tk.Label(pills, text=LANG_NAMES[l], bg=ACCENT if on else FAINT, fg=TOP if on else SUBFG,
                             font=fonts["small"], padx=8, pady=2, cursor="hand2")
                b.pack(side="left", padx=(0, 3))
                b.bind("<Button-1>", lambda e, l=l: set_language(l))

        foot = tk.Frame(tw, bg=PANEL, padx=18, pady=12)
        foot.pack(fill="x")
        if step is None:
            tbutton(foot, tr("Show tutorial"), lambda: open_tutorial(0), primary=True).pack(side="right")
            tbutton(foot, tr("Skip tutorial"), finish_tutorial).pack(side="left")
        else:
            last = step == n - 1
            tbutton(foot, tr("Finish") if last else tr("Next"),
                    finish_tutorial if last else (lambda: open_tutorial(step + 1)), primary=True).pack(side="right")
            if step > 0:
                tbutton(foot, tr("Back"), lambda: open_tutorial(step - 1)).pack(side="right", padx=(0, 6))
            dots = tk.Canvas(foot, width=n * 12, height=10, bg=PANEL, highlightthickness=0)
            dots.pack(side="left", pady=4)
            for i in range(n):                               # progress: done, current, to come
                col = ACCENT if i == step else (SUBFG if i < step else FAINT)
                dots.create_oval(i * 12 + 1, 1, i * 12 + 9, 9, fill=col, width=0)
        tk.Frame(tw, bg=PANEL, width=width, height=0).pack()   # keeps the card's width

    def keycap(c, x, y, text, h, w=None):
        """A keyboard key: rounded, outlined, label centred. Returns its width."""
        w = w or fonts["badge"].measure(text) + 12
        rrect(c, x, y, x + w, y + h, 4, fill=PANEL, outline=FAINT, width=1)
        c.create_line(x + 3, y + h, x + w - 3, y + h, fill=TOP)         # key shadow
        c.create_text(x + w / 2, y + h / 2, text=text, fill=FG, font=fonts["badge"])
        return w

    def draw_guide():
        """Footer: while the windows take clicks, an 'unlocked' banner with the key that locks
        them again. Returns its height (0 when locked)."""
        c, W = guide, L["W"] - 16
        c.delete("all")
        c.config(width=W)
        y, ls = 0, L["ls"]
        state["banner_box"] = None
        if not state["locked"]:                       # banner; its text wraps onto more lines
            c.create_text(10, y + 6, text=tr("UNLOCKED"), anchor="nw", fill=ACCENT, font=fonts["section"])
            t = c.create_text(10, y + ls + 8, anchor="nw", fill=SUBFG, font=fonts["small"], width=W - 20,
                              text=tr("Drag a title bar to move · click a player or an enemy"))
            ky, kh, x = c.bbox(t)[3] + 6, ls + 4, 10          # [Ctrl] + [Shift] + [M]  lock / unlock
            for i, key in enumerate((tr("Ctrl"), "Shift", "M")):
                if i:
                    c.create_text(x, ky + kh / 2, text="+", anchor="w", fill=DIM, font=fonts["small"])
                    x += fonts["small"].measure("+") + 4
                x += keycap(c, x, ky, key, kh) + 4
            c.create_text(x + 4, ky + kh / 2, text=tr("lock / unlock"), anchor="w", fill=SUBFG, font=fonts["small"])
            bh = ky + kh + 8 - y
            c.tag_lower(rrect(c, 0, y, W, y + bh, R, fill="#3a2a12"))
            state["banner_box"] = (y, y + bh)
            y += bh
        c.config(height=max(1, y))
        return y

    def raise_all():
        """Every overlay window shown back on top (above the game), in one fixed order: the meter
        at the bottom, the other windows over it, the dropdowns and the tour on top. All in one
        go (DeferWindowPos): raised one by one, windows that overlap trade places for a moment
        and a dropdown sinks under them until raised again, a flicker."""
        u = win.u
        hwnds = [win.hwnd] + [ov.hwnd for ov, on in ((dov, dshown["v"]), (hov, hist["open"]), (eov, eff["open"]),
                                                     (rov, rot["open"]), (wov, watch["shown"]),
                                                     (sov, score["shown"])) if on]
        hwnds += [u.GetAncestor(w.winfo_id(), 2) for w in (pick["win"], pick["tip"]) if w is not None]
        if menus["open"] is not None:
            hwnds.append(menus["open"][0].ov.hwnd)
        if tut["win"] is not None:
            hwnds += [tut["hlov"].hwnd, tut["ov"].hwnd]
        state["raise_hwnds"] = hwnds
        raise_hwnds(hwnds)

    def raise_hwnds(hwnds):
        """Win32 only (also called from foreground_thread): hwnds, bottom to top, above every other window."""
        u = win.u
        dwp, above = u.BeginDeferWindowPos(len(hwnds)), -1     # HWND_TOPMOST for the top one,
        for h in reversed(hwnds):                              # then each right under the one above
            if dwp:
                dwp = u.DeferWindowPos(dwp, h, above, 0, 0, 0, 0, 0x1 | 0x2 | 0x10)   # NOSIZE|NOMOVE|NOACTIVATE
            above = h
        if dwp:
            u.EndDeferWindowPos(dwp)

    def foreground_thread():
        """Another window came forward (a click on the game or another program; a topmost one covers
        ours): back on top at once, the windows raise_all last put there, and again from the next two
        refreshes, once it is done raising itself. Its own thread and message loop, never Tk's: a
        Python callback inside Tk's event loop that touches Tk crashes Python."""
        def on_foreground(*_):
            raise_hwnds(state.get("raise_hwnds") or [])
            state["reraise"] = 2
        hook = win.WINEVENTPROC(on_foreground)       # kept referenced while hooked
        win.u.SetWinEventHook(0x3, 0x3, None, hook, 0, 0, 0)    # EVENT_SYSTEM_FOREGROUND, OUTOFCONTEXT
        import ctypes.wintypes
        msg = ctypes.wintypes.MSG()
        while ctypes.windll.user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            pass
    threading.Thread(target=foreground_thread, daemon=True).start()
    root.bind_all("<ButtonRelease-1>", lambda e: state.update(reraise=2), add="+")   # a click on one of ours

    def redraw(w):
        """A list window drawn again at once, at its new size (the meter and the breakdown are
        redrawn every refresh anyway)."""
        if w == "rot" and rot["open"]:
            rot["ver"] = rot["rows"] = None
            draw_rot()
        elif w == "hist" and hist["open"]:
            hist["ver"] = hist["size"] = None
            draw_hist()
        elif w == "fx" and eff["open"]:
            eff["ver"] = eff["size"] = None
            draw_eff()

    def grip(top, w):
        """The bottom-right corner of window w: drag it to resize the window, not smaller than
        min_size (narrower than its text and icons need, they get smaller, down to mini); a
        double-click gives the window its own size again. Saved in view["sizes"]."""
        g = tk.Label(top, text="◢", bg=BG, fg=DIM, font=fonts.of("main")["small"], cursor="size_nw_se",
                     bd=0, padx=1, pady=0)
        st = {}

        def start(e):
            st.update(x=e.x_root, y=e.y_root, w=top.winfo_width(), h=top.winfo_height())

        def drag(e):
            mw, mh = min_size(w)
            size = [max(mw, st["w"] + e.x_root - st["x"]), max(mh, st["h"] + e.y_root - st["y"])]
            if view["sizes"].get(w) != size:
                view["sizes"][w] = size
                apply_sizes()
                top.geometry(f"{size[0]}x{size[1]}")
                redraw(w)

        def own_size(e):
            view["sizes"].pop(w, None)
            save_view(view)
            apply_sizes()
            redraw(w)
        g.bind("<Button-1>", start)
        g.bind("<B1-Motion>", drag)
        g.bind("<ButtonRelease-1>", lambda e: save_view(view))
        g.bind("<Double-Button-1>", own_size)
        g.bind("<Enter>", lambda e: g.config(fg=ACCENT))
        g.bind("<Leave>", lambda e: g.config(fg=DIM))
        return g
    grips = {"main": grip(root, "main"), "detail": grip(dwin, "detail"), "rot": grip(rwin, "rot"),
             "hist": grip(hwin, "hist"), "fx": grip(ewin, "fx")}

    def show_grips():
        """The meter's and the breakdown's only while unlocked (locked, clicks go through them)."""
        for w, g in grips.items():
            if w in ("main", "detail") and state["locked"]:
                g.place_forget()
            else:
                g.place(relx=1.0, rely=1.0, anchor="se")
                g.lift()

    def refresh():
        while not errq.empty():
            state["err"] = "capture: " + errq.get()
        while not events.empty():
            kind, val = events.get()
            if kind == "err":
                state["err"] = val
            elif val in actions:
                actions[val]()
        state["tick"] += 1
        if state["tick"] % 8 == 0:
            if net["paint"] and state["tab"] == "config":
                net["paint"]()
        if meter.check_idle() and state["hist"] is None:
            state["detail"], state["target"] = None, None
        enemies = D().enemy_bars(view["max_enemies"]) if view["enemy_hp"] else []
        state["enemy_ids"] = [e["aid"] for e in enemies]
        if state["target"] is not None and D().enemy_label(state["target"]) is None:
            state["target"] = None
        dur, players = D().snapshot(state["mode"], view["show_all"], state["target"])
        players = players[:MAX_PLAYERS]
        demo = tour_on() and not players                # the tour shows sample data until a fight starts
        if demo:
            dur, players = 83, demo_players(state["mode"])
            if view["enemy_hp"] and not enemies:
                enemies = demo_enemies()
                state["enemy_ids"] = [e["aid"] for e in enemies]
        state["players"] = players
        if view["auto_detail"] and state["hist"] is None and not demo and meter.t0 is not None and \
                meter.t0 != state.get("auto_t0"):        # a new fight: your details, once you are in it
            mine = next((r["aid"] for r in players if r.get("me")), None)
            if mine is not None:
                state["auto_t0"], state["detail"] = meter.t0, mine
                set_tab("meter")

        # title bar
        mode_b.config(text="D" if state["mode"] == "done" else "T")
        for b, tab in ((cfg_b, "config"), (win_b, "windows")):
            if b.base != (ACCENT if state["tab"] == tab else DIM):
                b.base = ACCENT if state["tab"] == tab else DIM
                b.config(fg=b.base)
        m, s = divmod(int(dur), 60)
        title.config(text={"config": tr("Settings"), "windows": tr("Windows")}.get(state["tab"], f"{m}:{s:02d}"))
        if state["tab"] == "windows":
            for paint in window_paints:
                paint()

        for k in need:
            need[k] = 0
        h = draw(players, enemies) if state["tab"] == "meter" else None

        # breakdown window
        if state["detail"] == PREVIEW and D().me:          # opened before the fight: now yours
            state["detail"] = next(iter(D().me))
        if state["detail"] is not None:
            if state["detail"] == PREVIEW:
                label, rows, summary = tr("Me"), [], dict(done=0, dps=0, crit=0, max_hit=0)
            elif state["detail"] < 0 and players and players[0]["aid"] < 0:     # sample player
                label, rows, summary = demo_details(state["detail"], players)
            else:
                tg = state["target"] if state["mode"] == "done" else None
                who = detail_who()
                small = not view[who]["skills"]          # minimized: only the heroes, not their skills
                label, rows, summary = D().details(
                    state["detail"], dict(view, **{who: dict(heroes=True, skills=False)}) if small else view, tg)
                if not rows and small:                   # no heroes (a monster): its skills
                    rows = D().details(state["detail"], dict(view, **{who: dict(heroes=False, skills=True)}), tg)[1]
            idx = next((i for i, r in enumerate(players) if r["aid"] == state["detail"]), None)
            if not view["me"]["skills"] and state["detail"] < 0:      # the tour's sample: its heroes
                rows = [r for r in rows if "hits" not in r] or rows
            args = (players[idx] if idx is not None else None, idx, len(players), label,
                    rows[:view["max_rows"]], summary)
            dh = draw_detail(*args)
            DL = L.of("detail")
            for _ in range(3):                        # text wider than the window: widen it, redraw
                if not need["detail"]:
                    break
                DL["DW"] += need["detail"]
                need["detail"] = 0
                dcan.config(width=DL["DW"])
                dh = draw_detail(*args)
            dwin.update_idletasks()
            pos = "" if dshown["placed"] else f"+{root.winfo_x() + root.winfo_width() + 10}+{root.winfo_y()}"
            dshown["placed"] = True
            dcan.config(scrollregion=(0, 0, DL["DW"], dh), yscrollincrement=DL["SKH"] + GAP)
            us = user_size("detail")
            if us:                                    # resized: that size, the rows scroll
                dwin.geometry(f"{us[0]}x{us[1]}{pos}")
            else:
                dcan.yview_moveto(0)
                dwin.geometry(f"{DL['DW']}x{dh + dhead.winfo_reqheight() + 14}{pos}")
            if dmin_b.cget("text") != detail_glyph():     # its size button follows the wrench's switch
                dmin_b.config(text=detail_glyph())
        # skill rotation (preview): its button on your own breakdown, its window redrawn on new casts
        mine = state["detail"] is not None and state["detail"] in D().me
        if mine != bool(rot_b.winfo_ismapped()):
            rot_b.pack(side="right", padx=1) if mine else rot_b.pack_forget()
        if rot["open"]:
            ver = (id(D()), D().rotation_ver, state["sizes_ver"], view["exact"],
                   view["rot_small"])
            if ver != rot["ver"] and state["tick"] % 4 == 0:
                rot["ver"] = ver
                draw_rot()
        base = ACCENT if rot["open"] else DIM          # the breakdown's rotation button lit while it is open
        if rot_b.base != base:                           # only on a change, so hovering still shows
            rot_b.base = base
            rot_b.config(fg=base)
        if hist["open"]:
            live = meter.fight_summary()
            ver = (meter.saved, state["hist_path"], state["hist"] is None, state["sizes_ver"],
                   view["exact"], view["lang"],
                   live and (live["name"], int(live["duration"]), live["team"], live["killed"]))
            if ver != hist["ver"] and state["tick"] % 4 == 0:
                hist["ver"] = ver
                draw_hist()
        if eff["open"]:                                  # Live counts down: every 0.5 s; the rest on changes
            ver = (id(D()), D().buff_ver, eff["tab"], view["fx_hidden"], tuple(view["watch"]), view["lang"],
                   state["sizes_ver"], state["detail"], state["target"],
                   state["tick"] // 2 if eff["tab"] == "live" else 0)
            if ver != eff["ver"]:
                eff["ver"] = ver
                draw_eff()
        draw_watch()
        draw_score()
        if (state["detail"] is not None) != dshown["v"]:
            dshown["v"] = state["detail"] is not None
            dov.show(dshown["v"])
            if not dshown["v"]:
                close_menu(dhead)
            if dshown["v"]:
                raise_all()

        # footer: errors and the key guide; the title dot shows the connection
        live = meter.packets and time.time() - meter.last_packet <= 10
        color = BAD if state["err"] else GOOD if (live and meter.key.confirmed is not None) else WARN
        dot.itemconfig(dot_id, fill=color)
        if state["err"]:
            err_l.config(text=state["err"])
            err_l.pack(fill="x", before=guide, pady=(0, 4))
        else:
            err_l.pack_forget()
        gh = draw_guide()
        root.update_idletasks()
        for _ in range(3):                            # text wider than the meter: widen it, redraw
            grow = max(need["main"], bar.winfo_reqwidth() - L["W"])
            if grow <= 0 or user_size("main"):
                break
            L["W"] += grow
            need["main"] = 0
            canvas.config(width=L["W"])
            err_l.config(wraplength=L["W"] - 16)
            for w, pad, wn in wrapped:
                if wn == "main":
                    w.config(wraplength=L["W"] - pad)
            if state["tab"] == "meter":
                h = draw(players, enemies)
            gh = draw_guide()
            root.update_idletasks()
        if gh:
            guide.pack(fill="x", pady=(4, 0))
        else:
            guide.pack_forget()
        root.update_idletasks()
        us = user_size("main")
        if h is None:
            h = (cfg if state["tab"] == "config" else wtab).winfo_reqheight()
        else:
            canvas.config(scrollregion=(0, 0, L["W"], h), yscrollincrement=bar_h() + GAP)
        if us and state["tab"] == "meter":            # resized: that size, the rows scroll
            root.geometry(f"{us[0]}x{us[1]}")
        else:                                         # (a settings tab shows in full)
            if not us:
                canvas.yview_moveto(0)
            root.geometry(f"{L['W']}x{h + bar.winfo_reqheight() + foot.winfo_reqheight() + 20}")
        if tour_on():
            update_tutorial()
        if update_ready.is_set():                # a new exe was installed: start it, then quit
            import subprocess
            subprocess.Popen([update_ready.exe], close_fds=True,
                             creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
            close()
            return
        if state["tick"] % 8 == 0 or state.get("reraise"):   # above the game: every 2 s, and after
            state["reraise"] = max(0, state.get("reraise", 0) - 1)   # another window came forward
            raise_all()
        root.after(250, refresh)

    update_ready = threading.Event()
    def on_update(exe):                          # updater thread: refresh() does the restart
        update_ready.exe = exe
        update_ready.set()
    updater.cleanup()
    updater.check(APP_VERSION, on_update, lambda text: meter.log(time.time(), text))

    apply_sizes()
    set_locked(view["start_locked"])
    refresh()
    if not view["tutorial_seen"]:
        root.after(400, lambda: open_tutorial(None))
    root.mainloop()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, help="only this game server TCP port")
    ap.add_argument("--ports", default="%d-%d" % DEFAULT_PORTS,
                    help="game server TCP port range (default %d-%d)" % DEFAULT_PORTS)
    ap.add_argument("--iface", help="capture adapter by name, e.g. Ethernet (default: the Cfg > Network choice)")
    ap.add_argument("--pcap", help="replay a capture file instead of live capture")
    ap.add_argument("--nogui", action="store_true", help="print results to the console")
    ap.add_argument("--list-ifaces", action="store_true")
    args = ap.parse_args()

    if args.list_ifaces:
        default = netif.default_ip()
        for name, ip in netif.adapters():
            print(f"{ip:<16} {name}" + ("   (default route)" if ip == default else ""))
        return
    if not npcap.available():
        msg = ("SDS Meter reads the game's traffic through Npcap, which is not installed.\n\n"
               "Install it from https://npcap.com (keep the default options), then start "
               "SDS Meter again.")
        if not args.nogui:
            import ctypes, webbrowser
            if ctypes.windll.user32.MessageBoxW(None, msg + "\n\nOpen the download page now?",
                                                "SDS Meter", 0x34) == 6:          # Yes
                webbrowser.open("https://npcap.com/#download")
        sys.exit(msg)

    meter, errq = Meter(), queue.Queue()
    meter.capture_done = False
    meter.ports = port_range(args)
    live = th = None
    if args.pcap:
        th = threading.Thread(target=pcap_thread, args=(args, meter, errq), daemon=True)
        th.start()
    else:
        live = LiveCapture(meter, errq, meter.ports)
        live.start(args.iface or load_view()["iface"])
    if not args.nogui:
        run_gui(meter, errq, live)
        return
    try:
        while th is None or th.is_alive() or not meter.capture_done:
            time.sleep(2) if th is None else th.join(2)
            if not args.pcap:
                print_text(meter)
            while not errq.empty():
                print("capture:", errq.get())
    except KeyboardInterrupt:
        pass
    print_text(meter)


def print_text(meter):
    """Same content as the overlay: every player, then each player's details."""
    view = load_view()
    dur, players = meter.snapshot("done", show_all=True)
    print(f"--- {meter.status()} | encounter {dur:.0f}s | pending {len(meter.pending_impacts)}")
    for i, r in enumerate(players, 1):
        pct = 100 * r["value"] / max(1, r["parent"])
        print(f"  {i}. {r['label']:<37} {r['value']:>12,} {pct:4.0f}%  {r['sub']}")
        if r["aid"] in meter.players or r["aid"] in meter.me:
            for d in meter.details(r["aid"], view)[1]:
                pad = "  " + "    " * d["level"]
                pct = 100 * d["value"] / max(1, d["parent"])
                print(f"{pad}{d['label']:<{40 - len(pad)}} {d['value']:>12,} {pct:4.0f}%  {d['sub']}")
    if meter.rotation:
        print("  skill rotation:")
        for g in meter.rotation_groups()[0]:
            print(f"    {int(g['t']) // 60}:{g['t'] % 60:04.1f}  {g['label'] + (f' x{g['n']}' if g['n'] > 1 else ''):<28}"
                  f" {g['hero'] or '':<10} {g['damage']:>12,}  {g['hits']} hits")


def report_crash(where=""):
    """The exe has no console: write the traceback to meter_crash.log and say so."""
    import ctypes, traceback
    path = os.path.join(USER, "meter_crash.log")
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"--- {time.strftime('%Y-%m-%d %H:%M:%S')} {where}\n{traceback.format_exc()}\n")
    except OSError:
        pass
    try:
        ctypes.windll.user32.MessageBoxW(None, f"SDS Meter hit an error{' in ' + where if where else ''}."
                                         f"\n\nDetails were saved to:\n{path}", "SDS Meter", 0x10)
    except (AttributeError, OSError):
        pass

        raise
