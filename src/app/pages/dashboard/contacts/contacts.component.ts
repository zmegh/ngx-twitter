import { Component, OnDestroy, OnInit, Input} from '@angular/core';
import { NbThemeService, NbMediaBreakpoint, NbMediaBreakpointsService } from '@nebular/theme';

import { UserService } from '../../../@core/data/users.service';
import { User } from "../../../@core/models/twitter.user";
import { ContactsInterface } from './contacts.interface.component';
import { Observable } from 'rxjs/Observable';

@Component({
  selector: 'ngx-contacts',
  styleUrls: ['./contacts.component.scss'],
  templateUrl: './contacts.component.html',
})

export class ContactsComponent implements OnInit, OnDestroy, ContactsInterface {

  private _countryCode = '';

  @Input()
  set countryCode(value: string) {
    console.log('countr code being set:' + value);
    this._countryCode = (value && value.trim()) || '<no name set>';
  }

  get countryCode(): string { return this._countryCode; }

  @Input() test: string;
  @Input() data: any;

  recent: any[];
  breakpoint: NbMediaBreakpoint;
  breakpoints: any;
  themeSubscription: any;

  constructor(private userService: UserService,
              private themeService: NbThemeService,
              private breakpointService: NbMediaBreakpointsService) {

    this.breakpoints = this.breakpointService.getBreakpointsMap();
    this.themeSubscription = this.themeService.onMediaQueryChange()
      .subscribe(([oldValue, newValue]) => {
        this.breakpoint = newValue;
      });
  }

  get contacts() {
    return this.userService.contacts.map((users: Array<User>) => users);
  }

  get currentCountry() {
    return this.userService.contacts.map((users: Array<User>) => users[0].country);
  }


  get json() {
    return this.userService.contacts.map((users: Array<User>) => users.length);
  }
  ngOnInit() {

    /*this.userService.getTwitterUsers(this.countryCode)
      .subscribe((users: any) => {
        if (!users || users[0] == null) return;

        users = users.sort(this.compare);

        this.contacts = [
          {user: users[0], type: users[0].followers},
          { user: users[1], type: 'home'},
          { user: users[2], type: 'mobile'},
          { user: users[3], type: 'mobile'},
          { user: users[4], type: 'home'},
          { user: users[5], type: 'work'},
        ];

        this.recent = [
          {user: users[0], type: 'home', time: '9:12 pm'},
        ];
      });*/
  }

  pullData() {

    let users = this.userService.pullTwitterUsers(this.countryCode);
    if (!users || users.length == 0) return;

    /*this.contacts = [
      { user: users[0], type: 'home' },
      { user: users[1], type: 'home' },
      { user: users[2], type: 'mobile' },
      { user: users[3], type: 'mobile' },
      { user: users[4], type: 'home' },
      { user: users[5], type: 'work' },
    ];*/

   // console.log('contacts count' + this.contacts.length);
  }

  ngOnDestroy() {
    this.themeSubscription.unsubscribe();
  }

   compare(a, b) {
     if (a.followers < b.followers)
      return 1;
     if (a.followers > b.followers)
      return -1;
    return 0;
  }
}
