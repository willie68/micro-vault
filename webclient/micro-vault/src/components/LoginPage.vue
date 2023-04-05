<script setup>
import { useLoginStore } from '../stores/login';

const loginStore = useLoginStore()

var username = ""
var password = ""
function submit() {
  console.info("submitted")
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
      <div class="grid">
        <div class="col">
          <div class="card">
            <img alt="Vault logo" class="logo" src="../assets/vault.svg" width="125" height="125" />
            <div class="center">
              <h1 >Micro Vault</h1>
            </div>
          </div>
        </div>
        <div class="col">
          <div class="card">
            <form class="flex flex-column gap-2">
              <h2>Please login</h2>
                <label for="username">Username</label>
                <InputText id="username" v-model="username" />
                <label for="password">Password</label>
                <Password v-model="password" inputId="password" :feedback="false"/>
                <Button icon="pi pi-check" label="submit" @click="submit()" />
            </form>
          </div>
        </div>
      </div>
    </template>
  </Card>
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
