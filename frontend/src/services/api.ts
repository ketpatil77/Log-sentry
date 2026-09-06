import type {Incident,Summary} from '../types/incident';
const API=(import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/$/,'');
async function json<T>(res:Response):Promise<T>{if(!res.ok){const body=await res.json().catch(()=>({detail:'Request failed'}));throw new Error(body.detail||'Request failed')} return res.json()}
export async function analyze(file:File){const data=new FormData();data.append('file',file);return json<{analysis_id:string;events_processed:number;incidents_found:number;log_type:string}>(await fetch(`${API}/api/analyze`,{method:'POST',body:data}))}
export const getSummary=(id:string)=>fetch(`${API}/api/analyses/${id}`).then(r=>json<Summary>(r));
export const getIncidents=(id:string)=>fetch(`${API}/api/analyses/${id}/incidents`).then(r=>json<Incident[]>(r));
export const getIncident=(id:string)=>fetch(`${API}/api/incidents/${id}`).then(r=>json<Incident>(r));
export const deleteAnalysis=(id:string)=>fetch(`${API}/api/analyses/${id}`,{method:'DELETE'}).then(r=>{if(!r.ok)throw new Error('Delete failed')});
