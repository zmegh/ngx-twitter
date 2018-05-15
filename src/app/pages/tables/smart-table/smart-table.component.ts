import { Component, NgModule } from '@angular/core';
import { LocalDataSource } from 'ng2-smart-table';
import { Headers, Response, Http, RequestOptions, URLSearchParams } from '@angular/http';
import { CustomSmartTablebuttonComponent } from './custom-smart-table-button-component';
import { CustomDropdownCellComponent } from './custom-dropdown-cell-component';
import { InvoiceService } from '../../../@core/data/invoice.service';
import { ModalComponent } from '../../ui-features/modals/modal/modal.component';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';

@NgModule({
  imports: [
    ModalComponent,
  ]
})

@Component({
  selector: 'ngx-smart-table',
  templateUrl: './smart-table.component.html',
  styles: [`
    nb-card {
      transform: translate3d(0, 0, 0);
    }
  `],
})
export class SmartTableComponent {

  url = 'http://localhost:49618/api/Invoice/';

  settings = {
    mode: external,
    actions: {
        add: false,
        edit: false,
        delete: false,
    },
    columns: {
      id: {
        title: 'Invoice No.',
        type: 'number',
      },
      invoiceDate: {
        title: 'Date',
        type: 'string',
      },
      customer: {
        title: 'Customer',
        type: 'string',
        width: '200px'

      },
      service: {
        title: 'Service',
        type: 'string',
      },
      statusText: {
        title: 'Status',
        type: 'string',
      },
      totalAmount: {
        title: 'Total Amount',
        type: 'number',
      },
      amountDue: {
        title: 'Amount Due',
        type: 'number',
      },
      button: {
        title: 'actions',
        type: 'custom',
        renderComponent: CustomSmartTablebuttonComponent,
        filter: false
      },
    },
  };

  source: LocalDataSource = new LocalDataSource();

  constructor(private invoiceService: InvoiceService, private modalService: NgbModal,
    private http: Http) {

    this.invoiceService
      .invoices()
      .then(result => this.source.load(result))
      .catch(error => console.log(error));

  }

  onDeleteConfirm(event): void {
    if (window.confirm('Are you sure you want to delete?')) {
      event.confirm.resolve();
    } else {
      event.confirm.reject();
    }
  }

  onCreate(event): void {

    let invoice = new invoiceObject();
    invoice.id = 23;
    invoice.customer = 'j doe';
    invoice.statusText = 'unpaid';
    invoice.service = 'fsfsdfsd';
    invoice.amountDue = 834.43;
    invoice.totalAmount = 343.3;
    invoice.invoiceDate = '23/03/2019';

    let data = new URLSearchParams();
    data.append('username', 'u');
    data.append('password', 'p');
    let headers = new Headers({ 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' });
    let options = new RequestOptions({ headers: headers });
    let invoices = [];
    invoices.push(invoice);
    this.http.post(this.url + 'insert', invoice, options).subscribe(res => {
      console.log('post sent');
    }, error => { console.error(error) });
  }

  onAction(event): void {
    alert(event);
  }

  onUserRowSelect(event): void {
    console.log(event);
  }

  showStaticModal() {
    const activeModal = this.modalService.open(CustomDropdownCellComponent, {
      size: 'sm',
      backdrop: 'static',
      container: 'nb-layout',
    });

    activeModal.componentInstance.modalHeader = 'Static modal';
    activeModal.componentInstance.modalContent = `This is static modal, backdrop click
                                                    will not close it. Click × or confirmation button to close modal.`;
    activeModal.componentInstance = CustomDropdownCellComponent;
  }

  onCustom(event) {
    alert(`Custom event '${event.action}' fired on row №: ${event.data.id}`)
  }
}
