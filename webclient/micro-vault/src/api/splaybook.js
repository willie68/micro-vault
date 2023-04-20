import sapi from './sapi'

const playbookEndpoint = 'playbook'

export default  {
  async upload(c) {
    const { data } = await sapi.client.post(`${playbookEndpoint}`, c)
    return data
  },

}
