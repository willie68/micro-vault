<script setup>
import DashBoard from './components/DashBoard.vue';
import LoginPage from './components/LoginPage.vue';
import Footer from './components/Footer.vue';
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
  <div class="fullsize">
    <LoginPage v-if="!loginStore.isLoggedIn"></LoginPage>
    <DashBoard v-if="loginStore.isLoggedIn"></DashBoard>
    <Toast />
    <Footer style="align: bottom"/>
  </div>
</template>

<style scoped>
.fullsize {
  min-width: 100vh;
  min-height: 100vh;
}
</style>
