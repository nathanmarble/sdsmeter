"""Decode a Seven Deadly Sins: Origin game-server capture (pcapng) into CSV.

Usage (from src/):  python -m sds_meter.decode <capture.pcapng> [server_port=10001]

Outputs next to the capture:
  <name>_hits.csv   one row per damage/heal result (P2C_ReportImpact, msg 10040, and
                    skill-object damage, msgs 10130/11054: ultimate bombs, elemental bursts)
  <name>_stats.csv  every stat sheet the server sent (P2C_ReportAbility, msg 10100)
  <name>_msgs.csv   every message: time, direction, id, name, length

Wire format (reverse engineered):
  [u16 len][u16 counter][u16 ?][u16 msg id][u32 flags][u32 time][u8 key][u16 body len]
  [body ... encrypted][6-byte trailer, also encrypted]   (len excludes the trailer)
  The key is recovered from the capture itself, so captures need a few hundred messages.
"""
import collections, csv, json, os, struct, sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # the project root

MSG_NAMES = {
    1: "C2P_HeartBeat?", 5: "P2C_HeartBeatAck", 6: "C2P_?6",
    10026: "C2P_ReportMove", 10029: "P2C_ReportDirectMove", 10030: "C2P_ReportStop",
    10031: "P2C_ReportStop", 10032: "C2P_RequestUseSkill", 10033: "P2C_ResultUseSkill",
    10036: "C2P_ReportActionStart", 10037: "C2P_ReportFire", 10038: "P2C_ReportFire",
    10039: "C2P_ReportImpact", 10040: "P2C_ReportImpact", 10041: "C2P_ReportSkillEnd",
    10042: "C2P_ReportCancelSkill", 10044: "P2C_SkillRemainedTime",
    10045: "C2P_ReportBattleState", 10046: "P2C_ReportBattleState",
    10048: "P2C_ReportBattleSetTarget", 10049: "P2C_ReportBuffInfoList",
    10050: "P2C_ReportRemoveBuffInfo", 10051: "C2P_ReportFindEnemy",
    10052: "P2C_ReportFindEnemy", 10059: "C2P_ReportActionMove",
    10060: "P2C_ReportActionMove", 10061: "P2C_ReportActionMoveStop",
    10062: "P2C_ReportProperty", 10100: "P2C_ReportAbility", 10133: "P2C_ReportAnimation",
    10292: "P2C_ReportMagicForceInfo", 10361: "P2C_ReportBuffResist",
    10414: "P2C_ReportTagPointInfo", 10415: "P2C_ReportTagPointUpdateStart",
    10416: "P2C_ReportTagPointUpdateStop", 10611: "C2P_ReportAnimation",
    10965: "P2C_ReportBurstData", 11005: "P2C_ReportBurstEndTime",
    11107: "P2C_ReportXigncode", 11108: "C2P_ReportXigncode",
    11118: "P2C_ReportBattleTransform",
    10130: "P2C_ReportObjectImpact?", 11054: "P2C_ReportObjectImpactList?",
    10883: "C2P_RequestToggleBattleLog", 10884: "P2C_ResultToggleBattleLog",
    10885: "P2C_ReportBattleLog", 10886: "P2C_ReportBattleLogTag",
    10887: "P2C_ReportBattleLogMagicForce",
}


def load_segments(pcap, port):
    from . import npcap
    streams, t0 = collections.defaultdict(list), []

    def seg(t, src, sport, dst, dport, seq, payload):
        t0[:] = t0 or [t]                                # times relative to the first segment
        direction = "S2C" if sport == port else "C2S"
        streams[direction].append((seq, t - t0[0], payload))
    npcap.read_file(pcap, (port, port), seg)
    return streams


def split_messages(segs):
    segs.sort()
    data, times, seen = bytearray(), [], set()
    for seq, t, p in segs:
        if seq in seen:
            continue
        seen.add(seq)
        data += p
        times += [t] * len(p)
    msgs, i = [], 0
    while i + 2 <= len(data):
        n = int.from_bytes(data[i:i + 2], "big") + 6
        if i + n > len(data):
            break
        msgs.append((times[i], bytes(data[i:i + n])))
        i += n
    return msgs


def build_table(all_msgs):
    col = [collections.Counter() for _ in range(256)]
    for _, m in all_msgs:
        if len(m) < 22:
            continue
        k = m[16]
        for o in range(19, len(m)):
            col[(k + o) % 256][m[o]] += 1
    return bytes(c.most_common(1)[0][0] if c else 0 for c in col)


def decrypt(m, T):
    if len(m) < 20:
        return m
    k = m[16]
    return m[:19] + bytes(m[o] ^ T[(k + o) % 256] for o in range(19, len(m)))


class Reader:
    def __init__(self, b):
        self.b, self.i = b, 0

    def u(self, fmt):
        v = struct.unpack_from(">" + fmt, self.b, self.i)[0]
        self.i += struct.calcsize(fmt)
        return v

    def wstr(self):
        n = self.u("H")
        s = self.b[self.i:self.i + n].decode("utf-16le", "replace").rstrip("\x00")
        self.i += n
        return s


def parse_impact(body):
    r = Reader(body)
    head = dict(caster=r.u("q"), skill_object=r.u("q"), skill_guid=r.u("i"),
                skill=r.wstr(), impact_index=r.u("i"), fire_index=r.u("i"),
                behavior_index=r.u("h"))
    targets = []
    for _ in range(r.u("H")):
        e = dict(target=r.u("q"), extra_caster=r.u("q"), damage_type=r.u("H"),
                 damage=r.u("q"), hp_after=r.u("q"), extra_hp=r.u("q"), ap=r.u("q"),
                 exhaust_shield_count=r.u("i"))
        for name in ("no_damage", "no_damage_no_local", "critical", "back_attack",
                     "block", "unk_flag", "reflect", "heal"):
            e[name] = r.u("B")
        e.update(impact_target_type=r.u("h"), sync_behavior=r.u("B"),
                 sub_area_index=r.u("h"), multi_hit_count=r.u("i"),
                 multi_hit_interval_ms=r.u("i"), burst_active=r.u("B"))
        # damage is the total for the entry; multi-hits are split evenly on screen
        e["damage_per_hit"] = e["damage"] // max(1, e["multi_hit_count"])
        targets.append(e)
    return head, targets


def parse_object_impact(mid, body):
    """10130 (one hit) / 11054 (several hits): damage dealt by a skill object
    (e.g. Tristan's ultimate bombs). Each hit has its own skill name, so one
    message can hold 'tristan_sworddual_skill_q_dmg' and 'fire_burstactivation_dmg'."""
    r = Reader(body)
    head = dict(caster=r.u("q"))
    if mid == 10130:
        target = r.u("q")
        head.update(skill_object=r.u("q"), impact_index=r.u("i"))
        count, targets = 1, [target]
    else:
        head.update(skill_object=r.u("q"), impact_index=r.u("i"))
        count, targets = r.u("H"), None
    out = []
    for i in range(count):
        # field names from the client's packet dump (m_SubAreaIndex ... m_ExtraCasterGUID)
        e = dict(target=targets[0] if targets else r.u("q"), sub_area_index=r.u("h"),
                 damage_type=r.u("h"), damage=r.u("q"), hp_after=r.u("q"), exhaust_shield_count=r.u("i"))
        for name in ("no_damage", "no_damage_no_local", "critical", "heal", "block", "block_shield"):
            e[name] = r.u("B")
        e.update(skill=r.wstr(), burst_active=r.u("B"), extra_caster=r.u("q"))
        out.append(e)
    return head, out


def parse_ability(body, abil_names):
    r = Reader(body)
    actor, hero, case = r.u("q"), r.u("q"), r.u("h")
    stats = {}
    for _ in range(r.u("H")):
        typ, val = r.u("I") & 0xFFFF, r.u("i")
        if typ != 0xFFFF:
            stats[abil_names.get(str(typ), f"type_{typ}")] = val
    return actor, hero, case, stats


def main():
    pcap = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 10001
    base = os.path.splitext(pcap)[0]
    abil_path = os.path.join(ROOT, "ability_types.json")
    abil_names = json.load(open(abil_path)) if os.path.exists(abil_path) else {}

    streams = load_segments(pcap, port)
    msgs = [(t, d, m) for d in streams for t, m in split_messages(streams[d])]
    msgs.sort(key=lambda x: x[0])
    T = build_table([(t, m) for t, d, m in msgs])
    msgs = [(t, d, decrypt(m, T)) for t, d, m in msgs]

    with open(base + "_msgs.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["time", "dir", "msg_id", "name", "len"])
        for t, d, m in msgs:
            mid = int.from_bytes(m[6:8], "big")
            w.writerow([f"{t:.3f}", d, mid, MSG_NAMES.get(mid, ""), len(m) - 6])

    hit_rows, stat_rows = [], []
    for t, d, m in msgs:
        mid = int.from_bytes(m[6:8], "big")
        body = m[19:]
        try:
            if mid == 10040:
                head, targets = parse_impact(body)
                for e in targets:
                    hit_rows.append({"time": f"{t:.3f}", "msg": mid, **head, **e})
            elif mid in (10130, 11054):
                head, targets = parse_object_impact(mid, body)
                for e in targets:
                    hit_rows.append({"time": f"{t:.3f}", "msg": mid, **head, **e})
            elif mid == 10100:
                actor, hero, case, stats = parse_ability(body, abil_names)
                for k, v in stats.items():
                    stat_rows.append({"time": f"{t:.3f}", "actor": actor, "hero": hero,
                                      "change_case": case, "stat": k, "value": v})
        except (struct.error, IndexError) as ex:
            print(f"warning: could not parse msg {mid} at {t:.3f}s: {ex}")

    for suffix, rows in (("_hits.csv", hit_rows), ("_stats.csv", stat_rows)):
        if rows:
            with open(base + suffix, "w", newline="", encoding="utf-8") as f:
                fields = list(dict.fromkeys(k for r in rows for k in r))
                w = csv.DictWriter(f, fieldnames=fields)
                w.writeheader()
                w.writerows(rows)
    print(f"{len(msgs)} messages, {len(hit_rows)} hit results, {len(stat_rows)} stat values")
    print("wrote", base + "_hits.csv", base + "_stats.csv", base + "_msgs.csv")


if __name__ == "__main__":
    main()
