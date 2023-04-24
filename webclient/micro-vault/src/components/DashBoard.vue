<script setup>
import ClientPage from './ClientPage.vue';
import GroupPage from './GroupPage.vue';
import KeysPage from './KeysPage.vue';
import PlaybookPage from './PlaybookPage.vue';
import InformationPage from './InformationPage.vue';
import { useLoginStore } from '../stores/login';
import { useConfirm } from "primevue/useconfirm";

const loginStore = useLoginStore()
const confirm = useConfirm();

const logout = () => {
  confirm.require({
    message: 'Do you want to logout from MicroVault?',
    header: 'Delete Logout',
    icon: 'pi pi-info-circle',
    acceptClass: 'p-button-danger',
    accept: () => {
      loginStore.logout
      window.location.reload()
    },
    reject: () => {
    }
  });

}
</script>

<template>
  <Toolbar>
    <template #start>
      <img alt="Vault logo" class="logo" src="../assets/vault.svg" width="50" />
      <Button text>Micro Vault Simple Admin Client</Button>
    </template>
    <template #end>
      <Button icon="pi pi-power-off" aria-label="Add Group" text @click="logout" />
    </template>
  </Toolbar>
  <TabView>
    <TabPanel header="Groups">
      <GroupPage></GroupPage>
    </TabPanel>
    <TabPanel header="Clients">
      <ClientPage></ClientPage>
    </TabPanel>
    <TabPanel header="Data">
      <KeysPage></KeysPage>
    </TabPanel>
    <TabPanel header="Playbook">
      <PlaybookPage></PlaybookPage>
    </TabPanel>
    <TabPanel header="Information">
      <InformationPage></InformationPage>
    </TabPanel>
  </TabView>
  <ConfirmDialog />
</template>

<style scoped>
.p-panel {
  width: 100%;
  min-width: 100%;
  height: 100%;
  min-height: 100%;
}
</style>