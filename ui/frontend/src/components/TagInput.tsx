import { useState, type KeyboardEvent } from "react";

interface Props {
  value: string[];
  onChange: (value: string[]) => void;
  placeholder?: string;
  id?: string;
}

export default function TagInput({ value, onChange, placeholder, id }: Props) {
  const [draft, setDraft] = useState("");

  const commit = () => {
    const trimmed = draft.trim();
    if (trimmed && !value.includes(trimmed)) {
      onChange([...value, trimmed]);
    }
    setDraft("");
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === "," || e.key === " ") {
      e.preventDefault();
      commit();
    } else if (e.key === "Backspace" && draft === "" && value.length > 0) {
      onChange(value.slice(0, -1));
    }
  };

  return (
    <div className="pill-input">
      {value.map((v) => (
        <span className="pill" key={v}>
          {v}
          <button type="button" onClick={() => onChange(value.filter((x) => x !== v))} aria-label={`Remove ${v}`}>
            ×
          </button>
        </span>
      ))}
      <input
        id={id}
        type="text"
        value={draft}
        placeholder={value.length === 0 ? placeholder : undefined}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={handleKeyDown}
        onBlur={commit}
      />
    </div>
  );
}
