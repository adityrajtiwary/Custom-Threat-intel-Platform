import axios from 'axios'

// FastAPI backend ka address (tera server IP + port 8000)
const API = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
})

export const getStats        = ()          => API.get('/stats').then(r => r.data)
export const getIOCs         = (params)    => API.get('/iocs', { params }).then(r => r.data)
export const getRecurring    = ()          => API.get('/iocs/recurring').then(r => r.data)
export const getIOCDetail    = (value)     => API.get(`/ioc/${encodeURIComponent(value)}`).then(r => r.data)
export const getCVEs         = (params)    => API.get('/cves', { params }).then(r => r.data)
export const getAPT          = ()          => API.get('/apt').then(r => r.data)
export const getArticles     = ()          => API.get('/articles').then(r => r.data)
export const getIOCTypeChart = ()          => API.get('/charts/ioc-types').then(r => r.data)
export const getSeverityChart= ()          => API.get('/charts/severity').then(r => r.data)

export default API
