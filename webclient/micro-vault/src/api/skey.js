import sapi from './sapi'

const groupkeysEndpoint = 'groupkeys'

export default  {
  async get(id) {
    const { data } = await sapi.client.get(`${groupkeysEndpoint}/${id}`)
    return data
  },
  async list() {
    const { data } = await sapi.client.get(`${groupkeysEndpoint}`)
    return data
  },
  async filter(g) {
    const { data } = await sapi.client.get(`${groupkeysEndpoint}?group=${g}`)
    return data
  },
  async createKey(g) {
    const { data } = await sapi.client.post(`${groupkeysEndpoint}`, {group:g})
    return data
  },
}
