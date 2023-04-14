import axios from 'axios'
import { useLoginStore } from '../stores/login';
import { useToast } from "primevue/usetoast";

/**
 * Service API
 * @see https://github.com/axios/axios
 */
const sapi = {
  init() {
    setAxiosDefaults()

    sapi.client = create()
    sapi.baseURL = axios.defaults.baseURL
    sapi.getStatus = getStatus
    sapi.isStatus = isStatus
    sapi.headers = headers
    sapi.message = message
    sapi.success = success
    sapi.warning = warning
    sapi.error = error

    return this
  },
}
export default sapi

/**
 * set defaults for an axios instance
 */
function setAxiosDefaults() {
  const loginStore = useLoginStore()
  axios.defaults.baseURL = loginStore.baseurl
  axios.defaults.headers.put['Content-Type'] = 'application/json'
  axios.defaults.headers.post['Content-Type'] = 'application/json'
  axios.defaults.headers.patch['Content-Type'] = 'application/json'
}

/**
 * creates an axios instance
 * @returns {object} axios instance
 */
function create() {
  const loginStore = useLoginStore()
  const config = {
    baseURL: loginStore.baseurl + "admin",
  }
  const srv = axios.create(config)
  srv.config = config
  srv.headers = function () {
    return headers(config.headers)
  }

  srv.interceptors.request.use(
    config => {
      config.headers = headers(config.headers)
      return config
    },
    err => {
      return Promise.reject(err)
    },
    {
      synchronous: true,
    }
  )

  srv.interceptors.response.use(
    res => {
      return res
    },
    err => {
      if (!err.config || !err.config.omitError) {
        sapi.error(err)
      }
      return Promise.reject(err)
    },
    {
      synchronous: true,
    }
  )
  return srv
}

/**
 * the default success handler
 * @returns {string} msg
 */
function success(msg) {
  console.log("succ:", msg)
  const toast = useToast();
  toast.add({ severity: "success", summary: 'service success', detail: msg, life: 3000 });
}

/**
 * the default warning handler
 * @returns {string} msg
 */
function warning(msg) {
  console.log("warn:", msg)
  const toast = useToast();
  toast.add({ severity: "warning", summary: 'service warning', detail: msg, life: 3000 });
}

/**
 * the default error handler
 * @returns {error} err
 */
function error(err) {
  const loginStore = useLoginStore()
  const msg = message(getStatus(err), getErrKey(err))
  if (getStatus(err) === 401) {
    loginStore.loggedIn = false
  }
  console.log("error:", msg)
  const toast = useToast();
  toast.add({ severity: "error", summary: 'service error', detail: msg, life: 3000 });
}

/**
 * checks an error status
 * @param {error} err - the error
 * @param {number} status - the status
 * @returns {boolean} true/false
 */
function isStatus(err, status) {
  return getStatus(err) === status
}

/**
 * gets an error key or undefined if none exists
 * @param {error} err - the error
 * @returns {string|undefined} the error key
 */
function getErrKey(err) {
  if (err.response?.data?.key) {
    return err.response.data.key
  }
}

/**
 * gets an error status or undefined if none exists
 * @param {error} err - the error
 * @returns {number|undefined} the status
 */
function getStatus(err) {
  if (err.response && err.response.status) {
    return err.response.status
  }
}

/**
 * returns a message for a status or a standard
 * message if no specific message is configured
 * @param {number} status - the status
 * @param {string} errKey - the error key (e.g., "name-conflict")
 * @returns {string} the message or default
 */
function message(status, errKey) {
  return status.toString() + " " + errKey
}

/**
 * gets the context specific headers from the state
 * @param {object} obj - optional headers to extend (gets copied)
 * @returns {object} headers
 */
function headers(obj) {
  const loginStore = useLoginStore()
  let headers = {}
  if (loginStore.tk) {
    headers.Authorization = `Bearer ${loginStore.tk}`
  }
  headers = obj ? Object.assign({}, headers, obj) : headers
  return headers
}
