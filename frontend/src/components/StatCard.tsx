import type {ReactNode} from 'react';
export default function StatCard({label,value,icon}:{label:string;value:number|string;icon:ReactNode}){return <article className="stat-card"><div className="stat-icon">{icon}</div><div><p>{label}</p><strong>{value}</strong></div></article>}
