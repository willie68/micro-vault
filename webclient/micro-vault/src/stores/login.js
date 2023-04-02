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
      if ((tk) && (rt)) {
        this.loggedIn = true
        this.token = tk
        this.refreshToken = rt
        console.log("tk:", this.token, "rt:", this.refreshToken)
      }
    },
    setBase(bu) {
      this.baseurl = bu
      console.log("base:", bu)
    }
  },
})
