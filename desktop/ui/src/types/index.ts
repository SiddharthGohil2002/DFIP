export type Role='ADMIN'|'INVESTIGATOR'|'ANALYST'|'VIEWER';
export interface User{_id:string;name:string;email:string;role:Role;status:string;}
export interface CaseItem{_id:string;case_id:string;name:string;description:string;status:string;priority:string;investigator_id?:string;created_at:string;updated_at:string;}
export interface Evidence{_id:string;evidence_id:string;case_id:string;filename:string;format:string;size:number;sha256:string;verification_status:string;created_at:string;}
export interface Notification{_id:string;title:string;message:string;read:boolean;created_at:string;}
