// i18n/LangContext.jsx
import { createContext, useContext, useState } from "react";
import { translations } from "./translations";

const LangContext = createContext(null);

export function LangProvider({ children }) {
  const saved = localStorage.getItem("ssk_lang") || "ko";
  const [lang, setLang] = useState(saved);

  const t = (key) => translations[lang]?.[key] ?? translations["ko"]?.[key] ?? key;

  const changeLang = (code) => {
    setLang(code);
    localStorage.setItem("ssk_lang", code);
  };

  return (
    <LangContext.Provider value={{ lang, t, changeLang }}>
      {children}
    </LangContext.Provider>
  );
}

export const useLang = () => useContext(LangContext);
