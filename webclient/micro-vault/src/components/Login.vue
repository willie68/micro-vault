<script setup>
import { useLoginStore } from '../stores/login';

const loginStore = useLoginStore()

var username = ""
var password = "" 
function submit() {
    console.info("submitted")
    var actionPostUrl =
          this.actionUrl + "/" + this.profile + "/" + this.actionName;
        var options = {
          method: "POST",
          body: JSON.stringify({
            profile: this.profile,
            action: this.actionName,
            page: this.page,
            command: "click",
          }),
          headers: {
            "Content-Type": "application/json",
          },
        };
        this.saveImg = "hourglass.svg";
        if (this.actionType != "MULTI") {
          console.log("set timeout");
          if (this.timerID) {
            clearTimeout(this.timerID);
            this.timerID = null;
          }
          this.timerID = setTimeout(() => (this.saveImg = ""), 20000);
        }
        let that = this;
        fetch(actionPostUrl, options)
          .then((res) => res.json())
          .then((data) => {
            console.log(that.actionType);
          })
          .catch((err) => console.log(err.message));
}

console.log("service url:" + loginStore.baseurl);
</script>

<template>
  <div class="grid">
    <div class="col bg-green-500">
      <div class="card">
        <img alt="Vault logo" class="logo" src="../assets/vault.svg" width="125" height="125" />
        <h1>Micro Vault</h1>
      </div>
    </div>
    <div class="col bg-green-500">
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


<style scoped></style>
