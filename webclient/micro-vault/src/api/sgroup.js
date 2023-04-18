import sapi from './sapi'

const groupsEndpoint = 'groups'

export default  {
  async get(id) {
    const { data } = await sapi.client.get(`${groupsEndpoint}/${id}`)
    return data
  },
  async list() {
    const { data } = await sapi.client.get(`${groupsEndpoint}`)
    return data
  },
  async store(g) {
    const { data } = await sapi.client.post(`${groupsEndpoint}`, g)
    return data
  },
  async delete(id) {
    const { data } = await sapi.client.delete(`${groupsEndpoint}/${id}`)
    return data
  },
}
