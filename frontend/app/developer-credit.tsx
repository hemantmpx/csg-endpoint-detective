import { Mail } from "lucide-react";

type DeveloperCreditProps = { className?: string };

export default function DeveloperCredit({ className = "" }: DeveloperCreditProps) {
  return (
    <div className={`developer-credit ${className}`.trim()}>
      <span className="developer-credit-name">Developed by <b>Hemant Upadhyay</b></span>
      <a className="developer-credit-contact" href="mailto:hupadhyay1s@semo.edu" aria-label="Contact Hemant Upadhyay about an issue">
        <Mail size={13} aria-hidden="true" />
        <span>Contact for issues</span>
        <b>hupadhyay1s@semo.edu</b>
      </a>
    </div>
  );
}
