import type {Severity} from '../types/incident';
export default function SeverityBadge({severity}:{severity:Severity}){return <span className={`badge badge-${severity.toLowerCase()}`}>{severity}</span>}
