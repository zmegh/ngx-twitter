import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { CustomSmartTablebuttonComponent } from './smart-table/custom-smart-table-button-component';
import { CustomDropdownCellComponent } from './smart-table//custom-dropdown-cell-component';
import { TablesComponent } from './tables.component';
import { SmartTableComponent } from './smart-table/smart-table.component';
import { ModalComponent } from '../ui-features/modals/modal/modal.component';
import { InvoiceFormComponent } from './invoices/invoice-form.component';

//import { HttpClientModule } from '@angular/common/http';

const routes: Routes = [{
  path: '',
  component: TablesComponent,
  children: [{
    path: 'smart-table',
    component: SmartTableComponent,
  },
    {
      path: 'invoices/new-invoice',
      component: InvoiceFormComponent,
    }],
}];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule],
})
export class TablesRoutingModule { }

export const routedComponents = [
  TablesComponent,
  SmartTableComponent,
  CustomSmartTablebuttonComponent,
  CustomDropdownCellComponent,
];
