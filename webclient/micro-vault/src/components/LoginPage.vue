<script setup>
import sapi from '../api/sapi';
import { useLoginStore } from '../stores/login';
import { useToast } from "primevue/usetoast";

const toast = useToast();
const loginStore = useLoginStore()

var username = ""
var password = ""
function submit() {
  var actionPostUrl = loginStore.baseurl + "login"
  var options = {
    method: "POST",
    body: JSON.stringify({
      user: username,
      pwd: btoa(password),
    }),
    headers: {
      "Content-Type": "application/json",
    },
  }
  //  let that = this;
  fetch(actionPostUrl, options)
    .then((res) => {
      if (res.ok) {
        return res.json()
      }
      return Promise.reject({ status: res.status, message: res.statusText })
    })
    .then((data) => {
      loginStore.afterlogin(data.access_token, data.refresh_token)
      sapi.init()
      toast.add({ severity: "success", summary: 'Logged in', detail: 'You’ve successfully logged into Micro-Vault Admin Interface.', life: 3000 });
    })
    .catch((err) => {
      console.log(err.status, err.message)
      toast.add({ severity: "error", summary: 'Login error', detail: err.message, life: 5000 });
    })
}

console.log("service url:" + loginStore.baseurl);
</script>

<template>
  <center>
    <br />
    <br />
    <br />
    <br />
    <Card style="width: 40em">
      <template #title>Micro-Vault Login</template>
      <template #content>
        <div class="grid">
          <div class="col">
            <div class="card">
              <img alt="Vault logo" class="logo" src="../assets/vault.svg" width="125" height="125" />
              <div class="center">
                <h1>Micro-Vault</h1>
              </div>
            </div>
          </div>
          <div class="col">
            <h2>Please login</h2>
            <div class="card" style="width: 400px">
              <div class="field grid">
                <label for="username" class="col-fixed">Username</label>
                <div class="col">
                  <InputText id="username" v-model="username" />
                </div>
              </div>
              <div class="field grid">
                <label for="password" class="col-fixed">Password</label>
                <div class="col">
                  <Password v-model="password" inputId="password" :feedback="false" />
                </div>
              </div>
              <div class="field grid">
                <div class="col">
                  <Button icon="pi pi-check" label="submit" @click="submit()" />
                </div>
              </div>
            </div>
          </div>
        </div>
      </template>
    </Card>
  </center>
</template>


<style scoped>
.center {
  display: block;
  align-content: center;
}

.logo {
  display: block;
  margin: 0 auto 2rem;
}
</style>
