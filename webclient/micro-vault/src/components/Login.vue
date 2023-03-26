<template>
<span class="p-float-label">
    <InputText id="username" v-model="value" />
    <label for="username">Username</label>
  </span>
  <br/>
  <span class="p-float-label">
    <Password v-model="password" inputId="password" />
    <label for="password">Password</label>
  </span>
</template>

<script>
export default {
  name: "Login",
  data() {
    return {
      username: "",
      password: "",
    };
  },
}
</script>

<style scoped>

</style>
