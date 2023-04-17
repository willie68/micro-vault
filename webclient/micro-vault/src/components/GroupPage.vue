<script setup>
import { useToast } from "primevue/usetoast";
import { ref } from "vue";
import sapi from '../api'

const toast = useToast();
const selectedGroup = ref();
const groups = ref([])
const selectedLabel = ref();
const labels = ref([])

groups.value.push({ "name": "unknown" })

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

getGroups()

</script>

<template>
    <div class="grid">
        <div class="col-2 justify-content-left">
            <h3>Groups</h3>
            <Listbox v-model="selectedGroup" :options="groups" optionLabel="name" class="w-full md:w-14rem"
                listStyle="max-height:250px; min-height:60vh" />
        </div>
        <div class="col-10 justify-content-left" v-if="selectedGroup">
            <h3>Group properties</h3>
            <table>
                <tr v-for="(value, key) in selectedGroup.label">
                    <td>{{ key }}</td>
                    <td><InputText v-model="selectedGroup.label[key]" ></InputText></td>
                </tr>
            </table>
        </div>
    </div>
</template>

<style scoped></style>