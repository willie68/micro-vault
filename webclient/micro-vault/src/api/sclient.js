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
}
