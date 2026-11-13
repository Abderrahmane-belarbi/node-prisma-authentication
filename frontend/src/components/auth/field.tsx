import { Eye, EyeOff } from "lucide-react";
import { useState } from "react";

export default function Field({
  label,
  id,
  type = "text",
  placeholder,
  value,
  onChange,
  autoComplete,
  required = true,
}: {
  label: string;
  id: string;
  type?: string;
  placeholder?: string;
  value: string;
  onChange: (value: string) => void;
  autoComplete?: string;
  required?: boolean;
}) {
  const [visible, setVisible] = useState(false);
  const secret = type === "password";
  return (
    <label className="field" htmlFor={id}>
      <span className="field-label">{label}</span>
      <span className="input-wrap">
        <input
          id={id}
          name={id}
          type={secret && visible ? "text" : type}
          placeholder={placeholder}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoComplete={autoComplete}
          required={required}
        />
        {secret && (
          <button
            type="button"
            className="reveal"
            aria-label={visible ? "Hide password" : "Show password"}
            onClick={() => setVisible(!visible)}
          >
            {visible ? <EyeOff size={17} /> : <Eye size={17} />}
          </button>
        )}
      </span>
    </label>
  );
}
