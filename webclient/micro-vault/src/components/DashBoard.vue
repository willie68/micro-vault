<script setup>
import ClientPage from './ClientPage.vue';
import GroupPage from './GroupPage.vue';
import KeysPage from './KeysPage.vue';
</script>

<template>
  <Panel>
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