<script setup>
import { useToast } from "primevue/usetoast";
import { ref, watch } from 'vue'
import sapi from '../api'

const toast = useToast();
const selectedGroup = ref()
const groups = ref([])
const clgroups = ref([])

async function getGroups() {
    let pgroups = sapi.sgroup.list()
    pgroups.then((data) => {
        toast.add({ severity: "success", summary: 'groups', detail: data, life: 3000 });
        console.log(data)
        data.forEach((g) => {
            groups.value.push(g)
        })
        selectedGroup.value = groups.value[0]
    })
}

async function getClients() {
    let pgroups = sapi.sclient.client4group(selectedGroup.value.name)
    pgroups.then((data) => {
        toast.add({ severity: "success", summary: 'clients', detail: data, life: 3000 });
        console.log(data)
        clgroups.value = []
        data.forEach((g) => {
            clgroups.value.push(g)
        })
    })
}

watch(selectedGroup, (selectedGroup, prevSelectedGroup) => {
    if (selectedGroup) {
        getClients()
    }
})

getGroups()

</script>

<template>
    <div class="grid">
        <div class="col-fixed justify-content-left" style="width: 240px">
            <h3>Groups</h3>
            <Listbox v-model="selectedGroup" :options="groups" optionLabel="name" class="w-full md:w-14rem"
                listStyle="max-height:250px; min-height:60vh" />
        </div>
        <div class="col-8 justify-content-left" v-if="selectedGroup">
            <h3>Group properties</h3>
            <table>
                <tr v-for="(value, key) in selectedGroup.label">
                    <td>{{ key }}</td>
                    <td><InputText v-model="selectedGroup.label[key]" ></InputText></td>
                </tr>
            </table>
        </div>
        <div class="col-2 justify-content-left" v-if="selectedGroup">
            <h3>Clients in this group</h3>
            <Listbox :options="clgroups" optionLabel="name"  class="w-full md:w-14rem"
                listStyle="max-height:250px; min-height:60vh" />
        </div>
    </div>
</template>

<style scoped></style>