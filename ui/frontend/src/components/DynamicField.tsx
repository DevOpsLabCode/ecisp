import type { FieldMeta } from "../types";
import TagInput from "./TagInput";

interface Props {
  field: FieldMeta;
  value: unknown;
  onChange: (name: string, value: unknown) => void;
}

export default function DynamicField({ field, value, onChange }: Props) {
  if (field.type === "bool") {
    return (
      <div className="field checkbox-field">
        <input
          id={field.name}
          type="checkbox"
          checked={Boolean(value)}
          onChange={(e) => onChange(field.name, e.target.checked)}
        />
        <label htmlFor={field.name} style={{ margin: 0 }}>
          {field.label}
        </label>
      </div>
    );
  }

  if (field.type === "multi") {
    return (
      <div className="field">
        <label htmlFor={field.name}>{field.label}</label>
        <TagInput
          id={field.name}
          value={Array.isArray(value) ? (value as string[]) : []}
          onChange={(v) => onChange(field.name, v)}
          placeholder="Type and press enter"
        />
        {field.help && <div className="help">{field.help}</div>}
      </div>
    );
  }

  if (field.type === "select") {
    return (
      <div className="field">
        <label htmlFor={field.name}>{field.label}</label>
        <select
          id={field.name}
          value={(value as string) ?? ""}
          onChange={(e) => onChange(field.name, e.target.value)}
        >
          {(field.options ?? []).map((opt) => (
            <option key={opt} value={opt}>
              {opt === "" ? "— none —" : opt}
            </option>
          ))}
        </select>
        {field.help && <div className="help">{field.help}</div>}
      </div>
    );
  }

  return (
    <div className="field">
      <label htmlFor={field.name}>
        {field.label}
        {field.required && " *"}
      </label>
      <input
        id={field.name}
        type={field.type === "password" ? "password" : "text"}
        value={(value as string) ?? ""}
        onChange={(e) => onChange(field.name, e.target.value)}
        autoComplete="off"
      />
      {field.help && <div className="help">{field.help}</div>}
    </div>
  );
}
