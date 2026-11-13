import { Check, Fingerprint, Sparkles } from "lucide-react";
import { Brand } from "./brand";


export function SideHero() {
  return (
    <aside className="visual-panel">
      <div className="visual-content">
        <Brand />
        <div className="visual-copy">
          <div className="visual-kicker">
            <Sparkles size={15} /> A little more clarity
          </div>
          <h2>
            Make room for
            <br />
            <em>what matters.</em>
          </h2>
          <p>
            One calm space to bring your work, your ideas, and your next big
            thing together.
          </p>
        </div>
        <div className="visual-card">
          <div className="orbit orbit-one" />
          <div className="orbit orbit-two" />
          <div className="visual-icon">
            <Fingerprint size={31} />
          </div>
          <div className="visual-card-copy">
            <span>YOUR SPACE, SECURED</span>
            <strong>Thoughtfully yours.</strong>
          </div>
          <div className="visual-card-check">
            <Check size={16} />
          </div>
        </div>
        <div className="visual-bottom">
          <span>© 2026 Northstar</span>
          <span>
            <span className="status-dot" /> All systems secure
          </span>
        </div>
      </div>
    </aside>
  );
}
