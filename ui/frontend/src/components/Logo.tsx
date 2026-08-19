interface Props {
  size?: number;
  className?: string;
}

/** Shield (security) + magnifying glass (discovery/scan) mark. */
export default function Logo({ size = 28, className }: Props) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-hidden="true"
    >
      <path
        d="M16 2.5 L27 6.8 V14.6 C27 22.6 21.4 28.4 16 30.3 C10.6 28.4 5 22.6 5 14.6 V6.8 Z"
        fill="#2c4a80"
        stroke="#4f8cff"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <circle cx="14" cy="13.6" r="4.3" fill="none" stroke="#e6edf3" strokeWidth="2" />
      <line x1="17.2" y1="16.8" x2="20.6" y2="20.2" stroke="#e6edf3" strokeWidth="2.2" strokeLinecap="round" />
    </svg>
  );
}
