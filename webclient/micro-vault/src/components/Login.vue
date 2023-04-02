<script setup>
import { useLoginStore } from '../stores/login';

const loginStore = useLoginStore()

var username = ""
var password = ""
function submit() {
  console.info("submitted")
  var actionPostUrl = loginStore.baseurl + "admin/login"
  var options = {
    method: "POST",
    body: JSON.stringify({
      user: this.username,
      pwd: btoa(this.password),
    }),
    headers: {
      "Content-Type": "application/json",
    },
  }
  //  let that = this;
  fetch(actionPostUrl, options)
    .then((res) => res.json())
    .then((data) => {
      console.log(data)
      loginStore.afterlogin(data.access_token, data.refresh_token)
    })
    .catch((err) => console.log(err.message))
}

console.log("service url:" + loginStore.baseurl);
</script>

<template>
  <Card style="width: 40em">
    <template #title>Micro Vault Login</template>
    <template #content>
    <div class="grid center">
      <div class="col">
        <div class="card">
          <img alt="Vault logo" class="logo" src="../assets/vault.svg" width="125" height="125" />
          <h1>Micro Vault</h1>
        </div>
      </div>
      <div class="col">
        <div class="card">
          <h2>Please login</h2>
          <form class="flex flex-column gap-2">
            <span class="p-float-label">
              <InputText id="username" v-model="username" />
              <label for="username">Username</label>
            </span>
            <span class="p-float-label">
              <Password v-model="password" inputId="password" />
              <label for="password">Password</label>
            </span>
            <span class="p-float-label">
              <Button icon="pi pi-check" label="submit" @click="submit()" />
            </span>
          </form>
        </div>
      </div>
    </div>
    </template>
  </Card>
</template>


<style scoped>
.center {
  align-content: center;
}
</style>
