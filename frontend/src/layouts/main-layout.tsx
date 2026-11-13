import { Outlet } from "react-router-dom";
import { SideHero } from "../components/side-hero"; 

export default function MainLayout() {
  return (
    <main className="auth-layout">
      <SideHero />
      <Outlet />
    </main>
  );
}
