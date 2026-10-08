import { Fingerprint } from 'lucide-react';
import { IS_DESKTOP } from '../lib/platform';

export function Logo({ sub }: { sub?: string }) {
  return (
    <div className="brand">
      <div className="brand-mark">
        <Fingerprint size={19} />
      </div>
      <div>
        <div className="brand-name">DFIP</div>
        <div className="brand-sub">{sub ?? (IS_DESKTOP ? 'Investigator desktop' : 'Investigation platform')}</div>
      </div>
    </div>
  );
}
