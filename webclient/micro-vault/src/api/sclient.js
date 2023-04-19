import sapi from './sapi'

const clientsEndpoint = 'clients'

export default  {
  async get(id) {
    const { data } = await sapi.client.get(`${clientsEndpoint}/${id}`)
    return data
  },
  async list() {
    const { data } = await sapi.client.get(`${clientsEndpoint}`)
    return data
  },
  async client4group(gr){
    const { data } = await sapi.client.get(`${clientsEndpoint}?group=${gr}`)
    return data
  },
  async delete(name) {
    const { data } = await sapi.client.delete(`${clientsEndpoint}/${name}`)
    return data
  },
  async new(c) {
    const { data } = await sapi.client.post(`${clientsEndpoint}`, c)
    return data
  },

}
