// hooks/useWalkAnim.js
export const WALK_CHARS = [
  { id:"walk_m",   label:"걷는 남성",        file:"walk_man.json",    emoji:"🚶‍♂️", preview:"🚶‍♂️" },
  { id:"walk_f",   label:"걷는 여성",        file:"walk_woman.json",  emoji:"🚶‍♀️", preview:"🚶‍♀️" },
  { id:"run_m",    label:"달리는 남성",      file:"run_man.json",     emoji:"🏃‍♂️", preview:"🏃‍♂️" },
  { id:"run_f",    label:"달리는 여성",      file:"run_woman.json",   emoji:"🏃‍♀️", preview:"🏃‍♀️" },
  { id:"zombie_w", label:"걷는 좀비",        file:"zombie_walk.json", emoji:"🧟",   preview:"🧟" },
  { id:"zombie_r", label:"달리는 좀비",      file:"zombie_run.json",  emoji:"🧟‍♂️",  preview:"🧟‍♂️" },
  { id:"santa_w",  label:"걷는 산타",        file:"santa_walk.json",  emoji:"🎅",   preview:"🎅" },
  { id:"santa_g",  label:"선물 뿌리는 산타", file:"santa_gift.json",  emoji:"🎅",   preview:"🎁" },
  { id:"archer",   label:"화살 쏘는 남자",   file:"archer.json",      emoji:"🏹",   preview:"🏹" },
  { id:"none",     label:"없음 (끄기)",      file:"",                 emoji:"",     preview:"✕" },
];

export const WALK_SPEEDS = [
  { id:"slow",   label:"느리게", multiplier:0.5, sec:14 },
  { id:"normal", label:"보통",   multiplier:1.0, sec:8  },
  { id:"fast",   label:"빠르게", multiplier:2.0, sec:4  },
];

const KEY_CHAR  = "ssk_walk_char";
const KEY_SPEED = "ssk_walk_speed";

export function getWalkChar()  { return localStorage.getItem(KEY_CHAR)  || "walk_m"; }
export function getWalkSpeed() { return localStorage.getItem(KEY_SPEED) || "normal"; }
export function setWalkChar(id)  { localStorage.setItem(KEY_CHAR, id); }
export function setWalkSpeed(id) { localStorage.setItem(KEY_SPEED, id); }
export function getWalkFile() {
  const id = getWalkChar();
  return WALK_CHARS.find(c => c.id === id)?.file || "";
}
export function getWalkEmoji() {
  const id = getWalkChar();
  return WALK_CHARS.find(c => c.id === id)?.emoji || "";
}
export function getWalkSec() {
  const id = getWalkSpeed();
  return WALK_SPEEDS.find(s => s.id === id)?.sec || 8;
}
