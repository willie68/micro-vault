<script setup>
import DashBoard from './components/DashBoard.vue';
import HelloWorld from './components/HelloWorld.vue'
import LoginPage from './components/LoginPage.vue';
import { useLoginStore } from './stores/login';

const loginStore = useLoginStore()
console.log(process.env.NODE_ENV)
if (process.env.NODE_ENV === "development") {
  var baseURL = "http://localhost:5173/api/v1/"
  loginStore.setBase(baseURL)
} else {
  var baseURL = window.location.protocol + "//" + window.location.hostname + ":" + window.location.port + "/api/v1/"
  loginStore.setBase(baseURL)
}
</script>

<template>
  <main>
    <Login v-if="!loginStore.isLoggedIn"></Login>
    <DashBoard v-if="loginStore.isLoggedIn"></DashBoard>
  </main>
</template>

<style scoped>
header {
  line-height: 1.5;
}

.logo {
  display: block;
  margin: 0 auto 2rem;
}

@media (min-width: 1024px) {
  header {
    display: flex;
    place-items: center;
    padding-right: calc(var(--section-gap) / 2);
  }

  .logo {
    margin: 0 2rem 0 0;
  }

  header .wrapper {
    display: flex;
    place-items: flex-start;
    flex-wrap: wrap;
  }
}
</style>
