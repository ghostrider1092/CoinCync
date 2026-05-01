import { createContext } from "react";
import { DARK } from "./utils/theme";

/** Shared React contexts — pulled out of `App.jsx` so any page module can
 *  import them without dragging the full `App` tree into the dep graph. */
export const ThemeCtx = createContext(DARK);
export const WalletCtx = createContext({});
export const NotifCtx = createContext({});
export const NavCtx = createContext({
  navigateTo: () => {},
});
