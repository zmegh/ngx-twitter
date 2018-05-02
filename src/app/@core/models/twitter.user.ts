export class User {
    id: number;
    screen_name: string;
    name: string;
    profile_image_url: string;
    friends_count : number;
    followers_count : number;
  statuses_count: number;
  country: string;

  constructor(
        id: number,
        screen_name: string,
        name: string,
        profile_image_url: string,
        friends_count: number,
        followers_count : number,
        statuses_count: number,
        country: string
  ) {
        this.id = id;
        this.screen_name = screen_name;
        this.name = name;
        this.profile_image_url = profile_image_url;
        this.friends_count = friends_count;
        this.followers_count = followers_count;
        this.statuses_count = statuses_count;
        this.country = country;
    }
}
