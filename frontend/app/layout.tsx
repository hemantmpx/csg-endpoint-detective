import type { Metadata } from "next";
import "./globals.css";
import "./themes.css";

// Run before paint so a saved preference never flashes the other theme.
const initializeTheme = `(function(){var media=window.matchMedia('(prefers-color-scheme: dark)');function apply(){var saved;try{saved=localStorage.getItem('csg-theme')}catch(e){}document.documentElement.dataset.theme=saved==='light'||saved==='dark'?saved:(media.matches?'dark':'light')}apply();media.addEventListener('change',apply);window.addEventListener('storage',function(e){if(e.key==='csg-theme')apply()})})()`;

export const metadata: Metadata = {
  title: "CSG Endpoint Detective",
  description: "Classroom endpoint-state reconciliation investigation lab",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en" data-scroll-behavior="smooth" suppressHydrationWarning><head><script dangerouslySetInnerHTML={{__html:initializeTheme}}/></head><body>{children}</body></html>;
}
