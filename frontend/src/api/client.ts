import axios from "axios";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8765";

export const api = axios.create({
  baseURL: API_BASE,
  headers: { "Content-Type": "application/json" },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("fstec_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem("fstec_token");
      localStorage.removeItem("fstec_user");
      if (window.location.pathname !== "/login") {
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);

export interface TokenResponse {
  access_token: string;
  token_type: string;
  role: string;
  username: string;
}

export interface UserResponse {
  id: number;
  username: string;
  full_name: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface StatsResponse {
  total_letters: number;
  hacker_letters: number;
  compromise_letters: number;
  vulnerability_letters: number;
  other_letters: number;
  total_threats: number;
  total_iocs: number;
  total_vulns: number;
}

export interface LetterListItem {
  id: number;
  letter_number: string;
  letter_date: string;
  letter_type: string;
  status: string;
  created_at: string;
  threat_count: number;
  ioc_count: number;
  vuln_count: number;
}

export interface AttachmentResponse {
  id: number;
  filename: string;
  file_type: string;
  parse_status: string;
  parse_errors: string;
  parsed_text: string;
}

export interface ThreatResponse {
  id: number;
  number: number;
  group_name: string;
  threat_type: string;
  theme: string;
  archive_name: string;
  exe_name: string;
  malware_type: string;
  description: string;
  measures: string;
}

export interface IoCResponse {
  id: number;
  ioc_type: string;
  value: string;
  context: string;
}

export interface VulnerabilityResponse {
  id: number;
  bdu_id: string;
  cve_id: string;
  description: string;
  software: string;
  severity: string;
  is_applicable: boolean | null;
  applicability_notes: string;
  action_type: string;
  action_details: string;
  response_point: string;
}

export interface VulnerabilityUpdateData {
  is_applicable?: boolean | null;
  applicability_notes?: string;
  action_type?: string;
  action_details?: string;
  response_point?: string;
  software?: string;
}

export interface LetterResponse {
  id: number;
  letter_number: string;
  letter_date: string;
  letter_type: string;
  status: string;
  subject: string;
  original_text: string;
  all_text: string;
  parse_errors: string;
  created_at: string;
  updated_at: string;
  attachments: AttachmentResponse[];
  threats: ThreatResponse[];
  iocs: IoCResponse[];
  vulnerabilities: VulnerabilityResponse[];
}

export const authApi = {
  login: (username: string, password: string) =>
    api.post<TokenResponse>("/api/auth/login", { username, password }),
  me: () => api.get<UserResponse>("/api/auth/me"),
  status: () =>
    api.get<{ needs_setup: boolean; user_count: number }>(
      "/api/auth/status"
    ),
};

export const lettersApi = {
  list: () => api.get<LetterListItem[]>("/api/letters"),
  stats: () => api.get<StatsResponse>("/api/letters/stats"),
  get: (id: number) => api.get<LetterResponse>(`/api/letters/${id}`),
  delete: (id: number) => api.delete(`/api/letters/${id}`),
  upload: (pdfFile: File, attachments: File[]) => {
    const formData = new FormData();
    formData.append("pdf_file", pdfFile);
    attachments.forEach((f) => formData.append("attachments", f));
    return api.post<LetterResponse>("/api/letters/upload", formData, {
      headers: { "Content-Type": "multipart/form-data" },
    });
  },
  generate: (id: number) => api.post(`/api/letters/${id}/generate`),
  getResponseText: (id: number) =>
    api.get<{ text: string; exists: boolean }>(`/api/letters/${id}/response/text`),
  getResponsePreview: (id: number) =>
    api.get<{
      title: string;
      intro: string;
      sections: Array<{
        threat_id: number;
        number: number;
        prefix: string;
        description: string;
        measures: string[];
        measures_preview: string[];
        threat_type: string;
        measure_options: string[];
        base_measures: string[];
        intro_text: string;
        section_text: string;
      }>;
    }>(`/api/letters/${id}/response/preview`),
  updateThreatMeasures: (letterId: number, threatId: number, measures: string[]) =>
    api.put<{ measures: string[] }>(`/api/letters/${letterId}/response/measures/${threatId}`, { measures }),
  download: (id: number) =>
    api.get(`/api/letters/${id}/download`, { responseType: "blob" }),
  updateResponse: (id: number, content: string) =>
    api.put(`/api/letters/${id}/response`, { content }),
  exportIocs: (id: number, type: string) =>
    api.get(`/api/letters/${id}/export/${type}`, { responseType: "blob" }),
  exportIocsDocx: (id: number, type: string) =>
    api.get(`/api/letters/${id}/export/${type}/docx`, { responseType: "blob" }),
  updateVulnerability: (letterId: number, vulnId: number, data: VulnerabilityUpdateData) =>
    api.put<LetterResponse>(`/api/letters/${letterId}/vulnerabilities/${vulnId}`, data),
};

export const usersApi = {
  list: () => api.get<UserResponse[]>("/api/users"),
  create: (data: { username: string; password: string; role: string; full_name: string }) =>
    api.post<UserResponse>("/api/users", data),
  update: (id: number, data: Partial<{ full_name: string; password: string; role: string; is_active: boolean }>) =>
    api.put<UserResponse>(`/api/users/${id}`, data),
  delete: (id: number) => api.delete(`/api/users/${id}`),
};

export interface ThreatTypeResponse {
  id: number;
  name: string;
  key: string;
  description: string;
  created_at: string;
}

export interface MeasureTemplateResponse {
  id: number;
  name: string;
  threat_type_id: number | null;
  measures: string;
  is_default: boolean;
  created_at: string;
  updated_at: string;
}

export interface VulnMeasureTemplateResponse {
  id: number;
  name: string;
  vuln_type_id: number | null;
  action_type: string;
  content: string;
  is_default: boolean;
  created_at: string;
  updated_at: string;
}

export interface VulnTypeResponse {
  id: number;
  name: string;
  key: string;
  description: string;
  created_at: string;
}

export const templatesApi = {
  listThreatTypes: () => api.get<ThreatTypeResponse[]>("/api/templates/threat-types"),
  createThreatType: (data: { name: string; key: string; description: string }) =>
    api.post<ThreatTypeResponse>("/api/templates/threat-types", data),
  updateThreatType: (id: number, data: Partial<{ name: string; description: string }>) =>
    api.put<ThreatTypeResponse>(`/api/templates/threat-types/${id}`, data),
  deleteThreatType: (id: number) => api.delete(`/api/templates/threat-types/${id}`),

  listMeasureTemplates: (threatTypeId?: number) =>
    api.get<MeasureTemplateResponse[]>("/api/templates/measure-templates", { params: threatTypeId ? { threat_type_id: threatTypeId } : {} }),
  createMeasureTemplate: (data: { name: string; threat_type_id: number | null; measures: string; is_default: boolean }) =>
    api.post<MeasureTemplateResponse>("/api/templates/measure-templates", data),
  updateMeasureTemplate: (id: number, data: Partial<{ name: string; threat_type_id: number; measures: string; is_default: boolean }>) =>
    api.put<MeasureTemplateResponse>(`/api/templates/measure-templates/${id}`, data),
  deleteMeasureTemplate: (id: number) => api.delete(`/api/templates/measure-templates/${id}`),

  listVulnTypes: () => api.get<VulnTypeResponse[]>("/api/templates/vuln-types"),
  createVulnType: (data: { name: string; key: string; description: string }) =>
    api.post<VulnTypeResponse>("/api/templates/vuln-types", data),
  updateVulnType: (id: number, data: Partial<{ name: string; description: string }>) =>
    api.put<VulnTypeResponse>(`/api/templates/vuln-types/${id}`, data),
  deleteVulnType: (id: number) => api.delete(`/api/templates/vuln-types/${id}`),

  listVulnTemplates: (vulnTypeId?: number) =>
    api.get<VulnMeasureTemplateResponse[]>("/api/templates/vuln-templates", { params: vulnTypeId ? { vuln_type_id: vulnTypeId } : {} }),
  createVulnTemplate: (data: { name: string; vuln_type_id: number | null; action_type: string; content: string; is_default: boolean }) =>
    api.post<VulnMeasureTemplateResponse>("/api/templates/vuln-templates", data),
  updateVulnTemplate: (id: number, data: Partial<{ name: string; vuln_type_id: number; action_type: string; content: string; is_default: boolean }>) =>
    api.put<VulnMeasureTemplateResponse>(`/api/templates/vuln-templates/${id}`, data),
  deleteVulnTemplate: (id: number) => api.delete(`/api/templates/vuln-templates/${id}`),
};
