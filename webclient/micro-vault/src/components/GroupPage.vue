<script setup>
import { useToast } from "primevue/usetoast";
import { ref } from "vue";
import sapi from '../api'

const toast = useToast();
const selectedGroup = ref();
var groups = []

groups.push({"name": "unknown"})

async function getGroups() {
    let pgroups = sapi.sgroup.list()
    pgroups.then((data) => {
        toast.add({ severity: "success", summary: 'groups', detail: data, life: 3000 });
        console.log(data)
        data.forEach((g) => {
            groups.push(g)
        })
        console.log(groups)
    }   
    )
}

getGroups()
</script>

<template>
    <h3>Groups</h3>
    <div class="card flex justify-content-left">
        <Listbox v-model="selectedGroup" :options="groups" optionLabel="name" class="w-full md:w-14rem" listStyle="max-height:250px; min-height:60vh" />
    </div>
</template>

<style scoped></style>