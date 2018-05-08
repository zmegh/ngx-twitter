import { Component } from '@angular/core';

@Component({
  selector: 'ngx-custom-dropdown-cell',
  template: `<select class="form-control" type="string">
      <option *ngFor="let customer of customers" [ngValue]="customer.ID">
      {{customer.firstName}}  {{ customer.lastName}}</option>
    </select>`,
})
export class CustomDropdownCellComponent {
  customers: Array<Object> = [
    { ID: 1, firstName: "joe", lastName: "shmoe" },
    { ID: 2, firstName: "larry", lastName: "blows" }
  ];

  /*get contacts() {
    return this.userService.contacts.map((users: Array<User>) => users);
  }*/
}
