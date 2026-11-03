"use client";

import * as React from "react";

import { Input } from "@/components/ui/input";
import { joinList, splitList } from "@/lib/forms";

/**
 * A comma separated list typed as text. The text is kept as typed while the field has
 * focus (so "a, " is not normalised away mid-word) and each change commits the parsed list.
 */
export function ListInput({
  value,
  onChange,
  id,
  placeholder,
  disabled,
  className,
  "aria-label": ariaLabel,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  id?: string;
  placeholder?: string;
  disabled?: boolean;
  className?: string;
  "aria-label"?: string;
}) {
  const [text, setText] = React.useState(joinList(value));
  const focused = React.useRef(false);
  React.useEffect(() => {
    if (!focused.current) setText(joinList(value));
  }, [value]);
  return (
    <Input
      id={id}
      aria-label={ariaLabel}
      disabled={disabled}
      placeholder={placeholder}
      className={className ?? "font-mono text-[12.5px]"}
      value={text}
      onFocus={() => (focused.current = true)}
      onBlur={() => {
        focused.current = false;
        setText(joinList(value));
      }}
      onChange={(e) => {
        setText(e.target.value);
        onChange(splitList(e.target.value));
      }}
    />
  );
}
