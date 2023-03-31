import { defineStore } from 'pinia'

export const useLoginStore = defineStore('login', {
  state: () => ({ 
    loggedIn: false, 
    token: '', 
    refreshToken: '',
    baseurl: '',
  }),
  getters: {
    isLoggedIn: (state) => state.loggedIn,
    tk: (state) => state.token,
    rt: (state) => state.refreshToken,
  },
  actions: {
    afterlogin(tk, rt) {
      this.loggedIn = true
      this.token = tk
      this.refreshToken = rt
    },
    setBase(bu) {
      this.baseurl = bu
    }
  },
})
