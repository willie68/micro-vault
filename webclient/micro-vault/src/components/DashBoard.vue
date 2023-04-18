<script setup>
import ClientPage from './ClientPage.vue';
import GroupPage from './GroupPage.vue';
import KeysPage from './KeysPage.vue';
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
  <Panel header="Micro Vault Simple Admin Client">
    <template #icons>
      <Button icon="pi pi-power-off" aria-label="Add Group" text @click="logout" />
    </template>
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
    </TabView>
  </Panel>
</template>

<style scoped>
.p-panel {
  width: 100%;
  min-width: 100%;
  height: 100%;
  min-height: 100%;
}
</style>