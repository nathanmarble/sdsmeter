# Seven Deadly Sins: Origin DPS Meter | SDS Meter

A real-time damage meter overlay for **Seven Deadly Sins: Origin** on Windows.
See how much damage everyone in your party deals, with a full breakdown per
hero and per skill, plus live enemy HP bars.

**THIS APP WILL STOP RECEIVING UPDATES ONCE OFFICIAL DPS METER IS RELEASED IN THE GAME**

<p align="center">
<a href="../../releases"><img src="https://img.shields.io/badge/Download-latest-4cc38a?style=for-the-badge&logo=windows&logoColor=white" alt="Download"></a>
<a href="#features"><img src="https://img.shields.io/badge/Features-2b303b?style=for-the-badge" alt="Features"></a>
<a href="#screenshots"><img src="https://img.shields.io/badge/Screenshots-2b303b?style=for-the-badge" alt="Screenshots"></a>
<a href="#installation"><img src="https://img.shields.io/badge/How%20to%20install-2b303b?style=for-the-badge" alt="How to install"></a>
<a href="#how-to-use"><img src="https://img.shields.io/badge/How%20to%20use-2b303b?style=for-the-badge" alt="How to use"></a>
<br>
<a href="#hotkey"><img src="https://img.shields.io/badge/Hotkey-2b303b?style=for-the-badge" alt="Hotkey"></a>
<a href="#windows"><img src="https://img.shields.io/badge/Windows-2b303b?style=for-the-badge" alt="Windows"></a>
<a href="#settings"><img src="https://img.shields.io/badge/Settings-2b303b?style=for-the-badge" alt="Settings"></a>
<a href="#faq"><img src="https://img.shields.io/badge/FAQ-2b303b?style=for-the-badge" alt="FAQ"></a>
<a href="#support-the-project"><img src="https://img.shields.io/badge/Support%20me-F96854?style=for-the-badge&logo=patreon&logoColor=white" alt="Support the project"></a>
<a href="#contact"><img src="https://img.shields.io/badge/Contact-2b303b?style=for-the-badge" alt="Contact"></a>
</p>

![SDS Meter](images/overlay.png)

> **Passive and safe by design.** SDS Meter only *reads* the game's network
> traffic. It never touches the game process: no memory reading, no injection,
> no packet changes, no automation. The overlay is an ordinary separate window
> on top of the game.

*SDS Meter is a fan-made tool and isn't affiliated with or endorsed by Netmarble.
Seven Deadly Sins: Origin and its assets belong to their respective owners. Even being a
passive overlay that doesn't touch the game, USE IT AT YOUR OWN RISK!*

---

## Support the project

If this tool has been useful to you, please consider supporting continued development:

[![Support on Patreon](https://img.shields.io/badge/Support%20on%20Patreon-F96854?style=for-the-badge&logo=patreon&logoColor=white)](https://www.patreon.com/sdsmeter)

Monthly or one-time: [patreon.com/sdsmeter](https://www.patreon.com/sdsmeter)

Your support keeps this project alive.

---

## Features

**Party damage, live**
- One row per player, ranked by damage, with total, DPS and share of the party.
  You are **Me** (orange bar); in dungeons and raids teammates are shown by
  their character name (⚙️ → Display → **Player names**), otherwise as
  **Player 2**, **Player 3**, … keeping their number when the ranking changes.
- Switch between **damage done** and **damage taken** with the **D / T** button
  in the title bar: click it and pick D (damage done) or T (damage taken).
- The fight timer runs from the first to the last hit (heals don't stretch it).
  After **60 seconds** in which your party deals and takes no damage, the live
  meter clears itself; the fight stays in the fight history. Reset by hand any
  time (also saved), and change the 60 s in the settings (0 = off).
- **Boss mode:** when a boss dies, the fight ends there: the timer stops at the
  kill and the fight is saved. The next fight starts with your party's next hit.
- Above the players the main window only shows the enemy HP bars; everything
  else lives in its own window, opened or closed with the **windows** button
  (🗗). The title bar keeps only D / T, windows, settings, help, reset, lock and
  close.

- **Guild boss (Demonic Beast Akumu):** its HP bar shows its level (Lv 1-30) and
  how often it was killed (at 1 HP it comes back with full, higher HP instead of
  dying); when it starts charging its ultimate, the watch bar counts down to the
  hit. A small **score window** (off by default: the windows button) follows your
  guild ranking points live during the run (1 point per 10,000 damage, rounded
  up like the server's), with the server's exact score at each level-up and the
  final score when the run ends. While it is on it stays up, also between runs,
  so you can place it beforehand.
- **Guild boss crystals:** the five crystals of its ultimate show in the enemy
  bars by element: Fire, Earth, Wind, Thunder and Ice crystal.

**Detailed breakdown**
- Open any player's panel to see damage per **hero** (with portraits; tag swaps
  are told apart). It opens minimized, with only the heroes; the size button in
  its title (the same switch as "Show each skill separately" in its wrench) also
  shows each **skill**, with the game's own skill icon: E, Q,
  Ultimate, passive, tag, normal and jump attacks, enchanted skills, combos and
  elemental bursts.
- Hits, average hit, crit rate, max hit and **overdamage** (damage wasted past
  the enemy's remaining HP).
- Gear set bonuses, weapon passives, pets, damage over time and elemental field
  effects are named the way the game names them.
- **Effects** (buffs and debuffs, by their in-game names in the meter's
  language), three ways:
  - **Live:** everything on you, your teammates and the enemies right now, with
    the time left, grouped by who it affects.
  - **Log:** every effect applied, in order, grouped by who put what on whom,
    with how long it lasted and whether it was re-applied while still on.
  - **Uptime:** how much of the fight each effect was up, one row per effect.
  - **Watch bar:** click any effect (or pick it by its icon) to watch it. A small
    bar always shows every watched effect: lit with its time left while it is on,
    dimmed while off, also effects the game itself doesn't show.
- **Graph tab:** damage over time for each player across the fight, with the
  boss's (or chosen enemy's) HP. *Combat data can be stored to improve the tool.*
- **Skill rotation:** every skill you cast, in order, with the key you pressed
  (the game's default keys: LMB, E, Q, R, Shift, 1-4) and the damage each cast
  dealt; a big view, or a small one with just the icons.

**Fight history**
- The fight going on is listed on top (**LIVE**), and every fight is saved when
  it ends (boss kill, reset, the 60 s idle clear, closing the meter), so it stays
  in the list after the main screen is cleared. Click one to see it again in the
  overlay, with its breakdown, effects, graph and rotation.
- **Export** a fight to a file to share it, and **Import** one (yours or a
  friend's) to look at it.

**Enemy HP bars**
- Every enemy your party hits gets a bar with its in-game name, HP %, HP left
  and max HP.
- Turn off **Details under the bars** (⚙️ → Display) for thinner, one-line bars:
  players keep their name, damage and %, enemies their name and HP %.
- **Damage to one enemy:** pick an enemy and the whole meter (players, DPS,
  breakdown) counts only the damage dealt to it. Useful for bosses with summons.

**Made to sit over the game**
- **Locked** mode is click-through and never takes focus from the game.
- Every overlay window stays above the game, also right after you click into
  another window.
- One hotkey, **Ctrl+Shift+M** (lock / unlock), that works while the game has focus.
- **Resizable windows:** drag a window's corner; text and icons shrink with it
  when it gets narrow, rows that don't fit scroll.
- Adjustable opacity, icon size and text size (mini → giant), exact or short
  numbers (4,820,000 or 4.82M).
- English, Português (BR), Français and Deutsch.
- A short tutorial on the first start (open it again any time with **?**).

---

## Screenshots

<table>
<tr>
<td align="center" valign="top"><img src="images/breakdown.png" width="300" alt="Damage breakdown"><br><sub><b>Breakdown:</b> damage per hero and per skill</sub></td>
<td align="center" valign="top"><img src="images/guildboss.png" width="340" alt="Guild boss"><br><sub><b>Guild boss:</b> level, kills, its crystals, the ultimate countdown and your score</sub><br><br>
<img src="images/graph.png" width="300" alt="Damage over time"><br><sub><b>Graph:</b> damage over time, with the boss's HP</sub><br><br>
<img src="images/history.png" width="300" alt="Fight history"><br><sub><b>Fight history:</b> every fight saved, the live one on top</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="images/rotation.png" width="300" alt="Skill rotation"><br><sub><b>Skill rotation:</b> every cast with its key, time and damage</sub></td>
<td align="center" valign="top"><img src="images/rotation_small.png" width="300" alt="Skill rotation, compact"><br><sub><b>Skill rotation, compact:</b> just the icons and keys</sub><br><br>
<img src="images/watchbar.png" width="240" alt="Watch bar"><br><sub><b>Watch bar:</b> your tracked effects, always in view</sub><br><br>
<img src="images/effect_picker.png" width="300" alt="Effect picker"><br><sub><b>Choose effects:</b> pick any effect by its icon</sub></td>
</tr>
<tr>
<td align="center" valign="top"><img src="images/effects_uptime.png" width="300" alt="Effect uptime"><br><sub><b>Effects, Uptime:</b> how long each buff and debuff was up</sub></td>
<td align="center" valign="top"><img src="images/effects_log.png" width="300" alt="Effect log"><br><sub><b>Effects, Log:</b> who put what on whom, and when</sub></td>
</tr>
</table>

---

## Requirements

- Windows 10 or 11
- **[Npcap](https://npcap.com/#download)**, the free capture driver Wireshark
  uses. If Wireshark is already installed, you already have it.
- The game in **windowed** or **borderless** mode (an overlay can't be drawn over
  exclusive fullscreen)

---

## Installation

1. **Install Npcap** from [npcap.com](https://npcap.com/#download) and keep the
   default options.
   - Leave *"Restrict Npcap driver's access to Administrators only"*
     **unchecked**. If you tick it, you have to run SDS Meter as administrator.
2. **Download** the latest `sds_meter.exe` from the [Releases](../../releases) page.
3. **Run** `sds_meter.exe`. No installer, nothing else to set up.
   - Windows SmartScreen may warn about an unknown publisher, because the exe
     isn't code-signed. Click **More info → Run anyway**.
4. **Start the game** (windowed or borderless) and get into a fight.

If Npcap is missing, SDS Meter tells you and offers to open the download page.

---

## How to use

1. Start SDS Meter, before or after the game.
2. The overlay shows **"Waiting for combat"** until damage happens. Hit
   something and the players appear.
3. Drag the title bar to move the overlay. Open the other windows you want with
   the **windows** button (🗗) and drag them into place, before a fight too;
   drag a window's corner (◢) to resize it. Then **lock** (**Ctrl+Shift+M**) so
   clicks go through to the game. Positions and sizes are saved.
4. Click a player (unlocked) for their breakdown; its **< >** buttons go
   through the players.
5. Press the reset button to reset between fights, or set an automatic reset in
   **⚙️**.

### How it works

The game client and server talk over the network, and the server tells your
client about every hit: who dealt it, to whom, with which skill, and for how
much. SDS Meter listens to that traffic through Npcap, decrypts the game's
messages, and adds the hits up per player, hero and skill. Your own character
is recognised from the stat sheets the server sends only to you, so teammates
playing the same heroes are never mistaken for you.

The decryption key is learned from the traffic itself and saved, so the meter
works straight away the next time; if a game update changes it, it is learned
again automatically.
Hits seen before the key is known are kept and counted once it is.

---

## Hotkey

**Ctrl+Shift+M** locks / unlocks the overlay (locked = click-through). It works
everywhere, also while the game has focus, and the UNLOCKED banner under the
meter shows it. Everything else is a click while the overlay is unlocked: a
player opens their breakdown, an enemy's bar counts only the damage dealt to it.

---

## Windows

The **windows** button (🗗) in the title bar lists every window with a switch
to open or close it: breakdown, skill rotation, effects, watch bar, fight
history, guild boss score. They open before a fight too (empty), so you can put
them in place; the score window stays up while it is on, also outside a run,
and while this list is open the watch bar shows even when empty, to drag it.

**Resize** the meter, breakdown, skill rotation, effects and fight history by
dragging their bottom-right corner (◢; the meter's and the breakdown's while
unlocked). Bars stretch with the width, rows that don't fit scroll with the
mouse wheel, and when a window gets narrower than its text and icons need they
get smaller by themselves, down to the smallest size where everything still
shows. Double-click the corner to give a window its own size back; **Reset
window positions** (⚙️) resets every size too. Positions and sizes are saved.

## Settings

Open them with **⚙️** in the title bar. Every change
applies immediately and is saved.

- **Display:** language, icon size, text size, exact numbers, player names, the
  details under the bars (DPS, crit, max hit, enemy HP; off for thinner,
  one-line bars), opacity.
- **General:** enemy HP bars and how many, **boss mode**, monsters in damage
  taken, start locked, **auto reset after N seconds idle**
  (60 by default), reset window positions.
- **Network adapter:** **All adapters (automatic)** by default. If you use a VPN
  or several network adapters and nothing shows up, pick the adapter you play on.
  A ● marks the one the game's traffic is coming in on.

A window with options of its own has a **wrench** (🔧) in its title:

- **Breakdown:** your details / teammate details: what it shows when maximized
  (each hero and/or each skill), opening yours when a fight starts, max rows.
- **Skill rotation:** compact view (only the icons).
- **Effects:** hidden effects, the watch bar.

---

## FAQ

**The meter says "Waiting for game traffic" and nothing appears.**
> Make sure the game is running and you're in a fight. In **⚙️ → Network
> adapter**, try picking the adapter you play on (VPNs like Radmin, Hamachi or
> ExitLag can get in the way). If you installed Npcap admin-only, run SDS Meter as
> administrator.

**I can't see the overlay over the game.**
> Set the game to **windowed** or **borderless** mode.

**My antivirus or SmartScreen flags the exe.**
> SDS Meter isn't code-signed and reads network traffic, which some antivirus
> programs treat as suspicious. It only listens for the game's traffic, and sends
> very little itself.

**Can I get banned for this?**
> SDS Meter is passive: it doesn't touch the game's memory, files or traffic, and
> it doesn't automate anything. Still, it's a third-party tool, so use it at your
> own discretion.

**Some skills show text instead of an icon.**
> Skills with no icon of their own in the game files (some gear bonuses, combos,
> new skills) are written out. New heroes get their icons in the next update.

**Is all of the code available?**
> Most of it, but not all. A few parts are left out of the shared source to avoid
> problems, and so are the game's files (icons, names, tags, etc) due to possible
> copyright issues.

---

## Contact

Bug reports and suggestions: [GitHub Issues](../../issues)

*SDS Meter is a fan-made tool and isn't affiliated with or endorsed by Netmarble.
Seven Deadly Sins: Origin and its assets belong to their respective owners.*
