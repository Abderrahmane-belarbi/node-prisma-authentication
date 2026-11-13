import { Fingerprint } from "lucide-react";

export function Brand() {
  return (
    <div className="brand" aria-label="Northstar home">
      <span className="brand-mark">
        <Fingerprint size={20} strokeWidth={2.2} />
      </span>
      <span>
        northstar<span className="brand-dot">.</span>
      </span>
    </div>
  );
}
