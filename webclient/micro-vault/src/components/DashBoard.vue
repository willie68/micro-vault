<script setup>
import ClientPage from './ClientPage.vue';
import GroupPage from './GroupPage.vue';
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
        <p>
          At vero eos et accusamus et iusto odio dignissimos ducimus qui blanditiis praesentium voluptatum deleniti atque
          corrupti quos dolores et quas molestias excepturi sint occaecati cupiditate non provident, similique sunt in
          culpa qui
          officia deserunt mollitia animi, id est laborum et dolorum fuga. Et harum quidem rerum facilis est et expedita
          distinctio. Nam libero tempore, cum soluta nobis est eligendi optio cumque nihil impedit quo minus.
        </p>
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