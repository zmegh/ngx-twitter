import { NgModule } from '@angular/core';
import { Ng2SmartTableModule } from 'ng2-smart-table';
import { ThemeModule } from '../../@theme/theme.module';
import { TablesRoutingModule, routedComponents } from './tables-routing.module';
import { SmartTableService } from '../../@core/data/smart-table.service';
import { InvoiceService } from '../../@core/data/invoice.service';
import { ModalComponent } from '../ui-features/modals/modal/modal.component';
import { InvoiceFormComponent } from './invoices/invoice-form.component';

@NgModule({
  imports: [
    ThemeModule,
    TablesRoutingModule,
    Ng2SmartTableModule,
    ModalComponent,
  ],

  declarations: [
    ...routedComponents,
    ModalComponent,
    InvoiceFormComponent,
  ],
  providers: [
    SmartTableService,
    InvoiceService,
  ],
})
export class TablesModule { }
