import axios from 'axios'

const API = axios.create({ baseURL: '/api' })

// har request me token auto-attach
API.interceptors.request.use((config) => {
  const token = localStorage.getItem('ti_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// 401 (token expire/invalid) -> logout
API.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response && err.response.status === 401) {
      localStorage.removeItem('ti_token')
      window.location.reload()
    }
    return Promise.reject(err)
  }
)

export const login = (username, password, otp) =>
  API.post('/login', { username, password, otp }).then(r => r.data)

export const getStats        = ()       => API.get('/stats').then(r => r.data)
export const getIOCs         = (params) => API.get('/iocs', { params }).then(r => r.data)
export const getRecurring    = ()       => API.get('/iocs/recurring').then(r => r.data)
export const getIOCDetail    = (value)  => API.get(`/ioc/${encodeURIComponent(value)}`).then(r => r.data)
export const getCVEs         = (params) => API.get('/cves', { params }).then(r => r.data)
export const getAPT          = ()       => API.get('/apt').then(r => r.data)
export const getArticles     = ()       => API.get('/articles').then(r => r.data)
export const getIOCTypeChart = ()       => API.get('/charts/ioc-types').then(r => r.data)
export const getSeverityChart= ()       => API.get('/charts/severity').then(r => r.data)

export default API
