<script setup>
import { useLoginStore } from '../stores/login';
import { useToast } from "primevue/usetoast";

import sgroup from '../api'
import sapi from '../api'

const loginStore = useLoginStore()
const toast = useToast();
/*
var actionPostUrl = loginStore.baseurl + "admin/groups"
var options = {
    method: "GET",
    headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ` + loginStore.tk,
    },
}
//  let that = this;
//fetch(actionPostUrl, options)
//    .then((res) => res.json())
//    .then((data) => {
//       //toast.add({ severity: "success", summary: 'groups', detail: data, life: 3000 });
//    })
//    .catch((err) => console.log(err.message))
*/
async function getGroups() {
    let groups = sapi.sgroup.list()
    groups.then((data) => {
        toast.add({ severity: "success", summary: 'groups', detail: data, life: 3000 });
    }
    )
}

getGroups()
</script>

<template>
    <h3>Groups</h3>
</template>

<style scoped></style>