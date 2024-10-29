import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from './dto';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt'
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config/envs';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {

    private readonly logger = new Logger('AuthService')

    constructor(
        private readonly jwtService: JwtService
    ) { super() }

    onModuleInit() {
        this.$connect()
        this.logger.log('MongoDB connected')
    }

    async signJWT(payload: JwtPayload) {
        return this.jwtService.sign(payload)
    }

    async verifyToken(token: string) {
        try {
            
            const {sub, iat, exp, ...user} = this.jwtService.verify(token, {
                secret: envs.jwtSecret,
            });

            return({
                user,
                token: await this.signJWT(user)
            })

        } catch (error) {
            console.log(error);
            throw new RpcException({
                status: 401,
                message: 'Invalid Token'
            })
            
        }
    }

    async registerUser(registerUserDto: RegisterUserDto) {

        const { email, name, password } = registerUserDto

        try {


            const user = await this.user.findUnique({
                where: { email }
            })

            if (user) {
                throw new RpcException({
                    status: 400,
                    message: 'User already exists'
                })
            }

            const newUser = await this.user.create({
                data: {
                    email,
                    password: bcrypt.hashSync(password, 10),
                    name
                }
            })

            const { password: ___, ...rest } = newUser

            return {
                user: rest,
                token: await this.signJWT(rest),
            }

        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            })
        }
    }

    async loginUser(loginUserDto: LoginUserDto) {
        const { email, password } = loginUserDto;

        const user = await this.user.findUnique({
            where: {
                email: email
            }
        });

        if (!user) {
            throw new RpcException({
                status: HttpStatus.UNAUTHORIZED,
                message: 'Wrong password or email'
            })
        }

        const isValidPassword = await bcrypt.compare(password, user.password)

        if (isValidPassword === false) {
            throw new RpcException({
                status: HttpStatus.UNAUTHORIZED,
                message: 'Wrong password or email'
            })
        } else {
            const { password: ___, ...rest } = user;
            return {
                user: rest,
                token: await this.signJWT(rest),
            }
        }
    }
}
